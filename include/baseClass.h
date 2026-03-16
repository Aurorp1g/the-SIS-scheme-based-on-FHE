/**
 * @file baseClass.h
 * @brief Base classes for the SIS scheme based on FHE
 * @details Defines core data structures including Result, Params, Norm, Picture, SharePic, and DecTools
 * @version 1.0
 * @date 2026
 * 
 * @note This file contains class declarations only. Implementations are in src/baseClass.cpp
 */

#pragma once
#include "tools.h"
#include <fstream>
#include "mymath.h"
#include "math_test.h"

#define ll long long
using namespace std;
using namespace seal;

/**
 * @class Result
 * @brief Stores execution results and timing information
 * @details Captures timing metrics for encoding, generation, and decoding operations
 *          along with correctness verification results
 */
class Result {
public:
    Result();
    
    /**
     * @brief Write result data to file
     * @param filename Output file path (default: "result.txt")
     */
    void writeResult(string filename = "result.txt");
    
    double encode0{};    ///< Encoding time for sharing phase
    double generate0{}; ///< Generation time for sharing phase
    double decode0{};   ///< Decoding time for sharing phase
    double encode1{};   ///< Encoding time for recovery phase
    double generate1{};  ///< Generation time for recovery phase
    double decode1{};   ///< Decoding time for recovery phase
    double correct{};   ///< Correctness percentage
    int l{};            ///< Image width
    int w{};            ///< Image height
    int t{};            ///< Threshold parameter
    int n{};            ///< Number of shares
    int p{};            ///< Modulus parameter
    int x_range{};      ///< X value range
    int poly_d0{};      ///< Polynomial degree for sharing
    int plain_m0{};     ///< Plain modulus for sharing
    int poly_d1{};      ///< Polynomial degree for recovery
    int plain_m1{};     ///< Plain modulus for recovery
};

/**
 * @class Params
 * @brief Parameters for the FHE-based SIS scheme
 * @details Contains all configuration parameters including image dimensions,
 *          encryption parameters, and scheme-specific settings
 */
class Params {
    friend class Picture;
    friend class SharePic;
    friend class DecTools;
public:
    Params();
    
    /**
     * @brief Construct Params with specified values
     * @param l Image width
     * @param w Image height
     * @param p Modulus P
     * @param n Parameter n
     * @param k Parameter k (threshold)
     * @param x X range
     */
    Params(int l = 2, int w = 2, int p = 251, int n = 6, int k = 4, int x = 10);
    
    /**
     * @brief Get image size
     * @return Pointer to array [width, height]
     */
    int* getSize();
    
    int getP() const;                  ///< @brief Get modulus P
    void setP(int P);                  ///< @brief Set modulus P
    int getN() const;                  ///< @brief Get parameter n
    void setN(int n);                  ///< @brief Set parameter n
    int getk() const;                  ///< @brief Get parameter k
    void setK(int K);                  ///< @brief Set parameter k
    int getXrange() const;             ///< @brief Get X range
    void setXrange(int range);         ///< @brief Set X range
    void setMaxLevel(int x);            ///< @brief Set maximum level
    int getMaxLevel() const;           ///< @brief Get maximum level
    void setScale(double scale);       ///< @brief Set scale
    double getScale() const;           ///< @brief Get scale
    int getBaseLenOfModulus() const;   ///< @brief Get base length of modulus
    void setBaseLenOfModulus(int len); ///< @brief Set base length of modulus
    int getBatches() const;            ///< @brief Get batch count
    void setBatch(int batches);        ///< @brief Set batch count

private:
    int L{}, W{};              ///< Image dimensions
    int ModP{};                ///< Modulus P
    int n{}, k{}, batches{};   ///< Scheme parameters
    int rangeX{};              ///< X range
    int maxLevel{};            ///< Maximum level
    double scale{};            ///< Scale factor
    int baseLenOfModulus{};    ///< Base length of modulus
};

/**
 * @class Norm
 * @brief Normalization and reference data for FHE operations
 * @details Contains encrypted constants and error tracking for BFV and CKKS schemes
 */
class Norm {
public:
    Norm();
    
    /**
     * @brief Construct Norm for BFV single-integer mode
     * @param encoder Batch encoder
     * @param encryptor Encryptor instance
     * @param parms Parameters
     */
    Norm(BatchEncoder& encoder, Encryptor& encryptor, Params& parms);
    
    /**
     * @brief Construct Norm for CKKS mode
     * @param encoder CKKS encoder
     * @param encryptor Encryptor instance
     * @param evaluator Evaluator instance
     * @param relin_keys Relinization keys
     * @param parms Parameters
     */
    Norm(CKKSEncoder& encoder, Encryptor& encryptor, Evaluator& evaluator,
         RelinKeys& relin_keys, Params& parms);
    
    /**
     * @brief Construct Norm for BFV batch mode
     * @param encoder Batch encoder
     * @param encryptor Encryptor instance
     * @param evaluator Evaluator instance
     * @param relin_keys Relinization keys
     * @param parms Parameters
     */
    Norm(BatchEncoder& encoder, Encryptor& encryptor, Evaluator& evaluator,
         RelinKeys& relin_keys, Params& parms);

    seal::Ciphertext zeros_en;      ///< Encrypted zeros
    seal::Ciphertext P_sen;         ///< Encrypted modulus P
    seal::Ciphertext one_en;        ///< Encrypted one (BFV)
    vector<seal::Ciphertext> ONES;  ///< Encrypted ones (CKKS)
    seal::Ciphertext ZERO;          ///< Encrypted zero (CKKS)
    int modP{};                     ///< Modulus P
    
    Error virError;                 ///< Virtual error
    Error realError;                ///< Real error
    vector<double> virErrorData;    ///< Virtual error data
    vector<double> realErrorData;   ///< Real error data
    vector<int> realErrorIndex;     ///< Real error indices
};

/**
 * @class Picture
 * @brief Represents a secret image for sharing
 * @details Stores original pixel data, encrypted data, and provides
 *          encryption/decryption functionality for BFV and CKKS schemes
 */
class Picture {
    friend class SharePic;
public:
    Picture();
    
    /**
     * @brief Construct Picture with parameters
     * @param parms Scheme parameters
     */
    explicit Picture(Params& parms);

    vector<ll>& getSec();              ///< @brief Get secret data
    vector<double> getSecFromDouble(); ///< @brief Get secret as double vector
    vector<Ciphertext> getSecEn();     ///< @brief Get encrypted data
    int* getSiz();                     ///< @brief Get image size

    /**
     * @brief Generate random picture data
     * @param parms Parameters
     * @param randRange Random range for alpha values
     */
    void generatePic(Params& parms, int randRange = 1);
    
    void PrintParms(vector<ll>& vec);                  ///< @brief Print parameters
    void pushCipher(const seal::Ciphertext& text);     ///< @brief Add ciphertext
    void printPic();                                   ///< @brief Print picture
    void pushPies(ll pixes, int index);                ///< @brief Set pixel value

    /**
     * @brief Decrypt picture using BFV scheme
     * @param decryptor Decryptor instance
     * @param encoder Batch encoder
     * @param evaluator Evaluator instance
     * @param norm Normalization data
     * @param finalRes Result to store timing
     * @param printAns Whether to print answer
     * @return Decrypted pixel values
     */
    vector<int> DecryPicBFV(Decryptor& decryptor, BatchEncoder& encoder,
                            Evaluator& evaluator, Norm& norm, Result& finalRes,
                            bool printAns = true);
    
    /**
     * @brief Decrypt picture using CKKS scheme
     * @param decryptor Decryptor instance
     * @param encoder CKKS encoder
     * @param evaluator Evaluator instance
     * @param norm Normalization data
     * @param finalRes Result to store timing
     * @param printAns Whether to print answer
     * @return Decrypted pixel values
     */
    vector<int> DecryPicCKKS(Decryptor& decryptor, CKKSEncoder& encoder,
                             Evaluator& evaluator, Norm& norm, Result& finalRes,
                             bool printAns = true);

    void setBatches(int batches);     ///< @brief Set batch count
    int getBatches() const;            ///< @brief Get batch count
    void setPic(vector<int> a);        ///< @brief Set picture data

    /**
     * @brief Compare with another picture
     * @param tem Picture to compare
     * @return Correctness percentage
     */
    double compare(const Picture& tem) const;
    
    /**
     * @brief Compare with another picture and compute error
     * @param tem Picture to compare
     * @param norm Normalization data for error
     * @return Mean error
     */
    double compare(const Picture& tem, Norm& norm) const;

private:
    vector<int> origin_pic;           ///< Original pixel data
    vector<ll> origin_sec, aerfa;     ///< Secret data and alpha
    vector<Ciphertext> pic_en;        ///< Encrypted picture
    int siz[2]{};                     ///< Image size [width, height]
    vector<double> origin_secCKKS;   ///< Secret data as doubles
    int batches{};                    ///< Batch count
};

/**
 * @class SharePic
 * @brief Represents a share in the secret sharing scheme
 * @details Contains share data (x, fx pairs) and provides encryption
 *          functionality for generating and revealing shares
 */
class SharePic {
public:
    friend class Picture;
    
    /**
     * @brief Construct SharePic with parameters
     * @param parms Scheme parameters
     */
    explicit SharePic(Params& parms);

    /**
     * @brief Add new pixel using plaintext
     * @param y Secret shares y
     * @param x X value
     * @param BFV Whether to store X (BFV mode)
     */
    void addNewPixByPlain(vector<ll> y, int x, bool BFV = true);
    
    vector<ll> getX();        ///< @brief Get X values
    vector<int> getfx();      ///< @brief Get fx values
    void PrintFx();           ///< @brief Print fx values

    /**
     * @brief Add new pixel using ciphertext
     * @param y Encrypted shares
     * @param evaluator Evaluator instance
     * @param rk Relinization keys
     * @param index Index
     * @return Reference to encrypted result
     */
    Ciphertext& addNewPixByCipher(vector<Ciphertext> y, Evaluator& evaluator,
                                  RelinKeys& rk, int index = 0);
    
    /**
     * @brief Generate CKKS shares
     * @param y Encrypted y values
     * @param evaluator Evaluator instance
     * @param rk Relinization keys
     * @param context SEAL context
     * @param ONES Encrypted ones
     * @return Encrypted share
     */
    Ciphertext generateCKKSShares(vector<Ciphertext> y, Evaluator& evaluator,
                                RelinKeys& rk, shared_ptr<seal::SEALContext>& context,
                                vector<Ciphertext>& ONES);
    
    /**
     * @brief Generate BFV shares
     * @param y Encrypted y values
     * @param evaluator Evaluator instance
     * @param rk Relinization keys
     * @param context SEAL context
     * @param ONES Encrypted one
     * @return Encrypted share
     */
    Ciphertext generateBFVShares(vector<Ciphertext> y, Evaluator& evaluator,
                               RelinKeys& rk, shared_ptr<seal::SEALContext>& context,
                               Ciphertext& ONES);

    /**
     * @brief Show and verify CKKS share
     * @param decryptor Decryptor instance
     * @param encoder CKKS encoder
     * @param printAns Whether to print answer
     */
    void showShareCKKS(Decryptor& decryptor, CKKSEncoder& encoder, bool printAns = true);
    
    /**
     * @brief Show and verify BFV share
     * @param decryptor Decryptor instance
     * @param encoder Batch encoder
     * @param printAns Whether to print answer
     */
    void showShareBFV(Decryptor& decryptor, BatchEncoder& encoder, bool printAns = true);

    vector<int> fx, fx_div;              ///< fx values and divided fx
    vector<ll> X;                        ///< X values
    int range_x{};                       ///< X range
    vector<Ciphertext> x_en, fx_en;      ///< Encrypted X and fx
    ll pix_de{}, pix_sr{};               ///< Pixel data
    int rad{};                           ///< Random value
    int P{};                             ///< Modulus
    int X_len{};                         ///< X length
    Plaintext X_plain, fx_plain;        ///< Plaintext X and fx
    vector<double> temVec;               ///< Temporary vector
};

/**
 * @class DecTools
 * @brief Decryption tools for recovery
 * @details Stores intermediate values (m, K, invm, A, KT, invKT)
 *          needed for polynomial reconstruction
 */
class DecTools {
public:
    vector<long long> m[64 * 64];    ///< Lagrange coefficients m
    vector<long long> K[64 * 64];    ///< Coefficients K
    vector<long long> invm[64 * 64]; ///< Inverse coefficients
    vector<long long> A[64 * 64];    ///< Accumulated coefficients
    long long KT[64 * 64]{};         ///< Product of m values
    long long invKT[64 * 64]{};      ///< Inverse of KT
};