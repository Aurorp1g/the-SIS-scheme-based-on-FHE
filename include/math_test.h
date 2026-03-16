/**
 * @file math_test.h
 * @brief Mathematical test and utility functions for CKKS and BFV operations
 * @details Provides core functions for ciphertext level management, polynomial multiplication,
 *          scale fitting, and arithmetic operations on encrypted data
 * @version 1.0
 * @date 2026
 */

#pragma once
#include<iostream>
#include<fstream>
#include<iomanip>
#include<math.h>
#include"tools.h"
#include "seal/seal.h"
using namespace std;
using namespace seal;

using parms_id_type = parms_id_type;

extern int limit[];

/**
 * @brief Get ciphertext level from context
 * @details Returns the chain index (level) of a ciphertext in the CKKS scheme
 * @param tem Ciphertext to query
 * @param context SEAL context
 * @param tag If 1, throws exception if level is 0 (cannot multiply further)
 * @return Chain index
 */
int getLevel(Ciphertext& tem, shared_ptr<seal::SEALContext>& context, int tag = 0);

/**
 * @brief Modify ciphertext scale and perform modulus switching
 * @param evaluator Evaluator instance
 * @param tem Ciphertext to modify
 * @param param_id Target parameter ID
 * @param scale Target scale
 */
void modifyCipScale(Evaluator& evaluator, Ciphertext& tem, parms_id_type param_id, double scale);

/**
 * @brief Resize to next power of 2
 * @param tem Input value
 * @return Resized value from limit array
 */
int reSize(int tem);

/**
 * @brief Multiply ciphertexts with rescaling (CKKS)
 * @details Performs multiplication, relinearization, and rescaling
 * @param tem1 First ciphertext (modified in-place)
 * @param tem2 Second ciphertext
 * @param evaluator Evaluator instance
 * @param relin_key Relinization keys
 */
void multiply(Ciphertext& tem1, Ciphertext tem2, Evaluator& evaluator, RelinKeys& relin_key);

/**
 * @brief Multiply ciphertexts without rescaling (BFV)
 * @param tem1 First ciphertext (modified in-place)
 * @param tem2 Second ciphertext
 * @param evaluator Evaluator instance
 * @param relin_key Relinization keys
 */
void multiply1(Ciphertext& tem1, Ciphertext tem2, Evaluator& evaluator, RelinKeys& relin_key);

/**
 * @brief Fit ciphertext sizes (variant 2)
 * @details Adjusts ciphertext scales and chain indices to match minimum level
 * @param vec Vector of ciphertexts
 * @param context SEAL context
 * @param ONES Vector of encrypted ones at different levels
 * @param evaluator Evaluator instance
 * @param relin_keys Relinization keys
 */
void fitSize2(vector<Ciphertext>& vec, shared_ptr<seal::SEALContext>& context, vector<Ciphertext>& ONES, Evaluator& evaluator, RelinKeys& relin_keys);

/**
 * @brief Fit ciphertext sizes to match levels
 * @details Aligns ciphertext chain indices by multiplying with ONES
 * @param vec Vector of ciphertexts
 * @param context SEAL context
 * @param ONES Vector of encrypted ones at different levels
 * @param evaluator Evaluator instance
 * @param relin_keys Relinization keys
 */
void fitSize(vector<Ciphertext>& vec, shared_ptr<seal::SEALContext>& context, vector<Ciphertext>& ONES, Evaluator& evaluator, RelinKeys& relin_keys);

/**
 * @brief Fit ciphertext sizes (variant 4)
 * @details Similar to fitSize but with different parameters
 * @param vec Vector of ciphertexts
 * @param context SEAL context
 * @param ONES Vector of encrypted ones
 * @param evaluator Evaluator instance
 * @param relin_keys Relinization keys
 */
void fitSize4(vector<Ciphertext>& vec, shared_ptr<seal::SEALContext>& context, vector<Ciphertext>& ONES, Evaluator& evaluator, RelinKeys& relin_keys);

/**
 * @brief Compute product of ciphertext vector (CKKS)
 * @details Performs tree-based multiplication with scale alignment
 * @param vec Vector of ciphertexts to multiply
 * @param evaluator Evaluator instance
 * @param relin_keys Relinization keys
 * @param context SEAL context
 * @param ONES Vector of encrypted ones
 * @return Product ciphertext
 */
Ciphertext cal_mut(vector<Ciphertext> vec, Evaluator& evaluator, RelinKeys& relin_keys, shared_ptr<seal::SEALContext>& context, vector<Ciphertext>& ONES);

/**
 * @brief Compute product of ciphertext vector (BFV)
 * @param vec Vector of ciphertexts to multiply
 * @param evaluator Evaluator instance
 * @param relin_keys Relinization keys
 * @param ONES Encrypted one
 * @return Product ciphertext
 */
Ciphertext cal_mutBFV(vector<Ciphertext> vec, Evaluator& evaluator, RelinKeys& relin_keys, Ciphertext& ONES);

/**
 * @brief Compute product of ciphertext vector (CKKS variant 1)
 * @param vec Vector of ciphertexts to multiply
 * @param evaluator Evaluator instance
 * @param relin_keys Relinization keys
 * @param context SEAL context
 * @param ONES Vector of encrypted ones
 * @param decryptor Decryptor instance
 * @param encoder CKKS encoder
 * @return Product ciphertext
 */
Ciphertext cal_mut1(vector<Ciphertext> vec, Evaluator& evaluator, RelinKeys& relin_keys, shared_ptr<seal::SEALContext>& context, vector<Ciphertext>& ONES, Decryptor& decryptor, CKKSEncoder& encoder);

/**
 * @brief Add ciphertexts with level alignment (in-place)
 * @param evaluator Evaluator instance
 * @param destinction Destination ciphertext
 * @param tem2 Source ciphertext
 * @param context SEAL context
 */
void add(Evaluator& evaluator, Ciphertext& destinction, Ciphertext& tem2, shared_ptr<seal::SEALContext>& context);

/**
 * @brief Subtract ciphertexts with level alignment (in-place)
 * @param evaluator Evaluator instance
 * @param destinction Destination ciphertext
 * @param tem2 Source ciphertext
 * @param context SEAL context
 */
void sub(Evaluator& evaluator, Ciphertext& destinction, Ciphertext& tem2, shared_ptr<seal::SEALContext>& context);

/**
 * @brief Add ciphertexts with level alignment (output)
 * @param evaluator Evaluator instance
 * @param tem1 First ciphertext
 * @param tem2 Second ciphertext
 * @param destinction Result ciphertext
 * @param context SEAL context
 */
void add(Evaluator& evaluator, Ciphertext& tem1, Ciphertext& tem2, Ciphertext& destinction, shared_ptr<seal::SEALContext>& context);

/**
 * @brief Subtract ciphertexts with level alignment (output)
 * @param evaluator Evaluator instance
 * @param tem1 First ciphertext
 * @param tem2 Second ciphertext
 * @param destinction Result ciphertext
 * @param context SEAL context
 */
void sub(Evaluator& evaluator, Ciphertext& tem1, Ciphertext& tem2, Ciphertext& destinction, shared_ptr<seal::SEALContext>& context);

/**
 * @brief Round to nearest integer
 * @param x Input value
 * @return Rounded integer
 */
int around(double x);