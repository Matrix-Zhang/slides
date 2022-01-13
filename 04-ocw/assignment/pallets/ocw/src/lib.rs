#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	//! A demonstration of an offchain worker that sends onchain callbacks
	use core::fmt;
	use frame_support::pallet_prelude::*;
	use frame_system::{
		offchain::{
			AppCrypto, CreateSignedTransaction, SendSignedTransaction,
			SignedPayload, Signer, SigningTypes,
		},
		pallet_prelude::*,
	};
	use parity_scale_codec::{Decode, Encode};
	use scale_info::prelude::string::String;
	use sp_core::crypto::KeyTypeId;
	use sp_runtime::{
		offchain as rt_offchain,
		traits::BlockNumberProvider,
		RuntimeDebug,
	};
	use sp_std::{
		collections::vec_deque::VecDeque,
		prelude::*,
		str::{self, FromStr},
	};

	use serde::{Deserialize, Deserializer};
	use sp_arithmetic::Permill;

	/// Defines application identifier for crypto keys of this module.
	///
	/// Every module that deals with signatures needs to declare its unique identifier for
	/// its crypto keys.
	/// When an offchain worker is signing transactions it's going to request keys from type
	/// `KeyTypeId` via the keystore to sign the transaction.
	/// The keys can be inserted manually via RPC (see `author_insertKey`).
	pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"demo");
	const NUM_VEC_LEN: usize = 10;

	const FETCH_TIMEOUT_PERIOD: u64 = 3000;

	const HTTP_DOT_PRICE_REMOTE_REQUEST: &str = "https://api.coincap.io/v2/assets/polkadot";

	type DotPrice = (u64, Permill);

	/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrapper.
	/// We can utilize the supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
	/// them with the pallet-specific identifier.
	pub mod crypto {
		use crate::KEY_TYPE;
		use sp_core::sr25519::Signature as Sr25519Signature;
		use sp_runtime::app_crypto::{app_crypto, sr25519};
		use sp_runtime::{traits::Verify, MultiSignature, MultiSigner};

		app_crypto!(sr25519, KEY_TYPE);

		pub struct TestAuthId;

		// implemented for ocw-runtime
		impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
			type RuntimeAppPublic = Public;
			type GenericSignature = sp_core::sr25519::Signature;
			type GenericPublic = sp_core::sr25519::Public;
		}

		// implemented for mock runtime in test
		impl
			frame_system::offchain::AppCrypto<
				<Sr25519Signature as Verify>::Signer,
				Sr25519Signature,
			> for TestAuthId
		{
			type RuntimeAppPublic = Public;
			type GenericSignature = sp_core::sr25519::Signature;
			type GenericPublic = sp_core::sr25519::Public;
		}
	}

	#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
	pub struct Payload<Public> {
		number: u64,
		public: Public,
	}

	impl<T: SigningTypes> SignedPayload<T> for Payload<T::Public> {
		fn public(&self) -> T::Public {
			self.public.clone()
		}
	}

	// ref: https://serde.rs/container-attrs.html#crate
	#[derive(Deserialize, Encode, Decode, Default)]
	struct GithubInfo {
		// Specify our own deserializing function to convert JSON string to vector of bytes
		#[serde(deserialize_with = "de_string_to_bytes")]
		login: Vec<u8>,
		#[serde(deserialize_with = "de_string_to_bytes")]
		blog: Vec<u8>,
		public_repos: u32,
	}

	#[derive(Debug, Deserialize, Encode, Decode, Default)]
	struct IndexingData(Vec<u8>, u64);

	pub fn de_string_to_bytes<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(de)?;
		Ok(s.as_bytes().to_vec())
	}

	pub fn de_string_to_dot_price<'de, D>(de: D) -> Result<DotPrice, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(de)?;
		let fields = s.split(".").collect::<Vec<&str>>();
		if fields.len() != 2 {
			return Err(serde::de::Error::custom("invalid format of dot price"));
		}
		let integer = u64::from_str(fields[0]).map_err(serde::de::Error::custom)?;
		let mut decimal_str = String::from(fields[1]);
		decimal_str.push_str("0000000");

		let decimal = Permill::from_parts(
			u32::from_str(&decimal_str[0..6]).map_err(serde::de::Error::custom)?,
		);

		Ok((integer, decimal))
	}

	impl fmt::Debug for GithubInfo {
		// `fmt` converts the vector of bytes inside the struct back to string for
		//   more friendly display.
		fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
			write!(
				f,
				"{{ login: {}, blog: {}, public_repos: {} }}",
				str::from_utf8(&self.login).map_err(|_| fmt::Error)?,
				str::from_utf8(&self.blog).map_err(|_| fmt::Error)?,
				&self.public_repos
			)
		}
	}

	#[pallet::config]
	pub trait Config: frame_system::Config + CreateSignedTransaction<Call<Self>> {
		/// The overarching event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		/// The overarching dispatch call type.
		type Call: From<Call<Self>>;
		/// The identifier type for an offchain worker.
		type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub (super) trait Store)]
	pub struct Pallet<T>(_);

	// The pallet's runtime storage items.
	// https://substrate.dev/docs/en/knowledgebase/runtime/storage
	#[pallet::storage]
	#[pallet::getter(fn numbers)]
	// Learn more about declaring storage items:
	// https://substrate.dev/docs/en/knowledgebase/runtime/storage#declaring-storage-items
	pub type Numbers<T> = StorageValue<_, VecDeque<u64>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn prices)]
	pub type Prices<T> = StorageValue<_, VecDeque<DotPrice>, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub (super) fn deposit_event)]
	pub enum Event<T: Config> {
		NewNumber(Option<T::AccountId>, u64),
		NewPrice(T::AccountId, DotPrice),
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		// Error returned when not sure which ocw function to executed
		UnknownOffchainMux,

		// Error returned when making signed transactions in off-chain worker
		NoLocalAcctForSigning,
		OffchainSignedTxError,

		// Error returned when making unsigned transactions in off-chain worker
		OffchainUnsignedTxError,

		// Error returned when making unsigned transactions with signed payloads in off-chain worker
		OffchainUnsignedTxSignedPayloadError,

		// Error returned when fetching github info
		HttpFetchingError,

		// Error returned when parse api body
		JsonParseError,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		/// Offchain Worker entry point.
		///
		/// By implementing `fn offchain_worker` you declare a new offchain worker.
		/// This function will be called when the node is fully synced and a new best block is
		/// succesfuly imported.
		/// Note that it's not guaranteed for offchain workers to run on EVERY block, there might
		/// be cases where some blocks are skipped, or for some the worker runs twice (re-orgs),
		/// so the code should be able to handle that.
		/// You can use `Local Storage` API to coordinate runs of the worker.
		fn offchain_worker(_: T::BlockNumber) {
			log::info!("Hello World from offchain workers!");

			// 这里使用签名交易，因为随意上传 token 对应的价格可能会有负面影响
			if let Err(e) = Self::offchain_signed_tx() {
				log::error!("offchain_worker error: {:?}", e);
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(10000)]
		pub fn submit_price_signed(origin: OriginFor<T>, price: DotPrice) -> DispatchResult {
			let who = ensure_signed(origin)?;
			log::info!("submit_price_signed: ({:?}, {:?})", price, who);
			Self::append_or_replace_price(price);
			Self::deposit_event(Event::NewPrice(who, price));
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		fn append_or_replace_price(price: DotPrice) {
			Prices::<T>::mutate(|prices| {
				if prices.len() == NUM_VEC_LEN {
					let _ = prices.pop_front();
				}
				prices.push_back(price);
				log::info!("Number vector: {:?}", prices);
			});
		}

		fn fetch_price_info() -> Result<DotPrice, Error<T>> {
			log::info!("sending request to: {}", HTTP_DOT_PRICE_REMOTE_REQUEST);

			let request = rt_offchain::http::Request::get(HTTP_DOT_PRICE_REMOTE_REQUEST);

			let timeout = sp_io::offchain::timestamp()
				.add(rt_offchain::Duration::from_millis(FETCH_TIMEOUT_PERIOD));

			let pending =
				request.deadline(timeout).send().map_err(|_| <Error<T>>::HttpFetchingError)?;

			let response = pending
				.try_wait(timeout)
				.map_err(|_| <Error<T>>::HttpFetchingError)?
				.map_err(|_| <Error<T>>::HttpFetchingError)?;

			if response.code != 200 {
				log::error!("Unexpected http request status code: {}", response.code);
				return Err(<Error<T>>::HttpFetchingError);
			}

			#[derive(Deserialize)]
			struct ResponseData {
				#[serde(rename = "priceUsd")]
				#[serde(deserialize_with = "de_string_to_dot_price")]
				price_usd: DotPrice,
			}

			#[derive(Deserialize)]
			struct JsonResponse {
				data: ResponseData,
			}

			let json_response =
				serde_json::from_slice::<JsonResponse>(&response.body().collect::<Vec<u8>>())
					.map_err(|_| <Error<T>>::JsonParseError)?;

			Ok(json_response.data.price_usd)
		}

		fn offchain_signed_tx() -> Result<(), Error<T>> {
			// We retrieve a signer and check if it is valid.
			//   Since this pallet only has one key in the keystore. We use `any_account()1 to
			//   retrieve it. If there are multiple keys and we want to pinpoint it, `with_filter()` can be chained,
			let signer = Signer::<T, T::AuthorityId>::any_account();

			// fetch dot price
			let price = Self::fetch_price_info()?;

			// `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
			//   - `None`: no account is available for sending transaction
			//   - `Some((account, Ok(())))`: transaction is successfully sent
			//   - `Some((account, Err(())))`: error occured when sending the transaction
			let result = signer.send_signed_transaction(move |_acct|
                // This is the on-chain function
                Call::submit_price_signed(price));

			// Display error if the signed tx fails.
			if let Some((acc, res)) = result {
				if res.is_err() {
					log::error!("failure: offchain_signed_tx: tx sent: {:?}", acc.id);
					return Err(<Error<T>>::OffchainSignedTxError);
				}
				// Transaction is sent successfully
				return Ok(());
			}

			// The case of `None`: no account is available for sending
			log::error!("No local account available");
			Err(<Error<T>>::NoLocalAcctForSigning)
		}
	}

	impl<T: Config> BlockNumberProvider for Pallet<T> {
		type BlockNumber = T::BlockNumber;

		fn current_block_number() -> Self::BlockNumber {
			<frame_system::Pallet<T>>::block_number()
		}
	}
}
