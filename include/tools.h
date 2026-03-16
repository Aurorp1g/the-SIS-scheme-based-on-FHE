/**
 * @file tools.h
 * @brief Utility functions for error calculation and ciphertext I/O
 * @details Provides helper functions for error analysis, vector printing,
 *          and ciphertext/ptext serialization
 * @version 1.0
 * @date 2026
 */

#pragma once
#include<iostream>
#include<vector>
#include<fstream>
#include<iomanip>
#include<string>
#include<seal/seal.h>
using namespace std;
using namespace seal;

/**
 * @struct Error
 * @brief Error statistics structure
 * @details Stores statistical metrics for error analysis
 */
struct Error {
    double total;      ///< Sum of all error values
    double mean;       ///< Mean error
    double var;        ///< Variance of errors
    double maxn;       ///< Maximum error
    int dataScale;     ///< Number of data points
};

/**
 * @brief Print vector of doubles
 * @param vec Vector to print
 * @param num Number of elements to show from start and end
 * @param pres Precision for floating point output
 */
void print_vec(vector<double>&vec,int num,int pres=4);

/**
 * @brief Print vector of integers
 * @param vec Vector to print
 * @param num Number of elements to show from start and end
 * @param pres Precision for floating point output
 */
void print_vec(vector<int>& vec, int num, int pres = 4);

/**
 * @brief Print blank lines
 * @param tag Number of blank lines to print
 */
void print_line(int tag = 1);

/**
 * @brief Print decrypted CKKS ciphertext vector
 * @param decryptor Decryptor instance
 * @param encoder CKKS encoder
 * @param en Ciphertext to decrypt and print
 */
void PrintDeVec(Decryptor& decryptor, CKKSEncoder& encoder, Ciphertext& en);

/**
 * @brief Print multiple decrypted CKKS ciphertext vectors
 * @param decryptor Decryptor instance
 * @param encoder CKKS encoder
 * @param en Vector of ciphertexts
 * @param tag Whether to print multiple elements per ciphertext
 * @param num Number of elements to print
 */
void PrintDeVec(Decryptor& decryptor, CKKSEncoder& encoder, vector<Ciphertext>& en, int tag = 1, int num = 4);

/**
 * @brief Calculate error statistics for double vector
 * @param vec Input vector
 * @return Error structure with statistics
 */
Error cal_err(vector<double>& vec);

/**
 * @brief Calculate error statistics for integer vector
 * @param vec Input vector
 * @return Error structure with statistics
 */
Error cal_err(vector<int> vec);

/**
 * @brief Print error statistics
 * @param err Error structure to print
 */
void printError(Error& err);

/**
 * @brief Output ciphertexts to files
 * @param text Vector of ciphertexts
 * @param filePre Filename prefix
 * @param context SEAL context
 */
inline void outPutCiphertext(const std::vector<seal::Ciphertext>& text,
                             const std::string& filePre,
                             std::shared_ptr<seal::SEALContext> context);

/**
 * @brief Output plaintexts to files
 * @param text Vector of plaintexts
 * @param filePre Filename prefix
 */
void outPutCiphertext(vector<Plaintext>& text, string filePre);