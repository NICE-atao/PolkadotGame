use frame_support::{pallet_prelude::*, traits::Currency};
use frame_system::pallet_prelude::*;
use sp_std::prelude::*;

#[pallet::pallet]
pub struct Pallet<T>(_);

#[pallet::config]
pub trait Config: frame_system::Config {
    type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
}

#[pallet::storage]
pub type Scores<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u32, ValueQuery>;

#[pallet::event]
#[pallet::generate_deposit(pub(super) fn deposit_event)]
pub enum Event<T: Config> {
    ScoreUpdated(T::AccountId, u32),
}

#[pallet::error]
pub enum Error<T> {
    None,
}

#[pallet::hooks]
impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

#[pallet::call]
impl<T: Config> Pallet<T> {
    #[pallet::weight(10_000)]
    pub fn update_score(origin: OriginFor<T>, score: u32) -> DispatchResult {
        let sender = ensure_signed(origin)?;
        Scores::<T>::insert(&sender, score);
        Self::deposit_event(Event::ScoreUpdated(sender, score));
        Ok(())
    }
}
