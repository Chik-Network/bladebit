#pragma once

#include "BLS.h"

#define CHIK_PUZZLE_HASH_SIZE   32
#define CHIK_ADDRESS_MAX_LENGTH 63 // 4 (hrp) + 1 (separator) + 52 (data) + 6 (checksum)
                                   // hrp is either xck or txck

 #define CHIK_ADDRESS_LENGTH         62
 #define CHIK_TESTNET_ADDRESS_LENGTH 63

struct XckAddress : NBytes<CHIK_ADDRESS_LENGTH+1>
{};

struct PuzzleHash : NBytes<CHIK_PUZZLE_HASH_SIZE>
{
    static bool FromAddress( PuzzleHash& hash, const char address[CHIK_ADDRESS_MAX_LENGTH+1] );

    void ToAddress( char address[CHIK_ADDRESS_MAX_LENGTH+1] );
    std::string ToAddressString();

    void ToHex( char hex[CHIK_PUZZLE_HASH_SIZE+1] ) const;
    std::string ToHex() const;

    static bool FromHex( const char hex[CHIK_PUZZLE_HASH_SIZE*2+1], PuzzleHash& outHash );

};

class KeyTools
{
public:
    static bool HexPKeyToG1Element( const char* hexKey, bls::G1Element& pkey );

    static bls::PrivateKey MasterSkToLocalSK( const bls::PrivateKey& sk );

    static void PrintPK( const bls::G1Element&  key );
    static void PrintSK( const bls::PrivateKey& key );
};

