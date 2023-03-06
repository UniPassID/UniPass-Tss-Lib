use curv::{
    arithmetic::Converter,
    elliptic::curves::{Point, Scalar, Secp256k1},
    BigInt,
};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two;
use serde::{de, Deserialize, Serialize, Serializer};

pub mod keygen;
pub mod sign;

#[derive(Debug, Serialize, Deserialize)]
pub struct PaillierPublic {
    pub ek: EncryptionKey,
    #[serde(
        deserialize_with = "deserialize_bigint",
        serialize_with = "serialize_bigint"
    )]
    pub encrypted_secret_share: BigInt,
}

/// Public encryption key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncryptionKey {
    #[serde(
        deserialize_with = "deserialize_bigint",
        serialize_with = "serialize_bigint"
    )]
    pub n: BigInt, // the modulus
    #[serde(
        deserialize_with = "deserialize_bigint",
        serialize_with = "serialize_bigint"
    )]
    pub nn: BigInt, // the modulus squared
}

pub fn deserialize_point<'de, D>(deserializer: D) -> Result<Point<Secp256k1>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: String = de::Deserialize::deserialize(deserializer)?;
    let point_bytes = base64::decode(&s)
        .map_err(|e| de::Error::custom(format!("deserialize call failed:{:?}", e)))?;
    Ok(Point::<Secp256k1>::from_bytes(&point_bytes)
        .map_err(|e| de::Error::custom(format!("deserialize call failed:{:?}", e)))?)
}

pub fn serialize_point<S>(v: &Point<Secp256k1>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&base64::encode(&*v.to_bytes(true)))
}

pub fn deserialize_scalar<'de, D>(deserializer: D) -> Result<Scalar<Secp256k1>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: String = de::Deserialize::deserialize(deserializer)?;
    let scalar_bytes = base64::decode(&s)
        .map_err(|e| de::Error::custom(format!("deserialize call failed:{:?}", e)))?;
    Ok(Scalar::<Secp256k1>::from_bytes(&scalar_bytes)
        .map_err(|e| de::Error::custom(format!("deserialize call failed:{:?}", e)))?)
}

pub fn serialize_scalar<S>(v: &Scalar<Secp256k1>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&base64::encode(&*v.to_bytes()))
}

pub fn deserialize_bigint<'de, D>(deserializer: D) -> Result<BigInt, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: String = de::Deserialize::deserialize(deserializer)?;
    let bigint_bytes = base64::decode(&s)
        .map_err(|e| de::Error::custom(format!("deserialize call failed:{:?}", e)))?;
    Ok(BigInt::from_bytes(&bigint_bytes))
}

pub fn serialize_bigint<S>(v: &BigInt, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&base64::encode(&v.to_bytes()))
}

pub fn deserialize_paillier_public<'de, D>(
    deserializer: D,
) -> Result<party_two::PaillierPublic, D::Error>
where
    D: de::Deserializer<'de>,
{
    let paillier_public = PaillierPublic::deserialize(deserializer)?;
    Ok(unsafe { std::mem::transmute(paillier_public) })
}

pub fn serialize_paillier_public<S>(
    v: &party_two::PaillierPublic,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let paillier_public: PaillierPublic = unsafe { std::mem::transmute_copy(v) };
    let res = paillier_public.serialize(serializer);
    std::mem::forget(paillier_public);
    res
}
