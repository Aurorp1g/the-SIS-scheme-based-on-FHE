/**
 * @file mymath.h
 * @brief Mathematical utility functions for polynomial operations
 * @details Provides functions for polynomial evaluation, Lagrange interpolation,
 *          and encrypted polynomial operations for BFV and CKKS schemes
 * @version 1.0
 * @date 2026
 */

#pragma once
#include<cmath>
#include<ctime>
#include<vector>
#include "seal/seal.h"
#include"math_test.h"

using namespace std;
using namespace seal;

/**
 * @brief Check noise budget of ciphertext
 * @param decryptor Decryptor instance
 * @param xx Ciphertext to check
 */
void check1(Decryptor& decryptor, Ciphertext xx);

/**
 * @brief Fast modular exponentiation
 * @param base Base value
 * @param mi Exponent
 * @param MOD Modulus
 * @return base^mi mod MOD
 */
long long mypow(long long base, int mi, int MOD);

/**
 * @brief Compute difference polynomial coefficients (integer version)
 * @details Computes D where D[i][j] = product of (x_i - x_j) for j != i
 * @param X Input vector (will be negated in-place)
 * @param k Size parameter
 * @return Flattened D matrix
 */
vector<int> getD(vector<int>& X, int k);

/**
 * @brief Compute difference polynomial coefficients (double version)
 * @param X Input vector (will be negated in-place)
 * @param k Size parameter
 * @return Flattened D matrix
 */
vector<double> getD(vector<double>& X, int k);

/**
 * @brief Compute difference polynomial coefficients (BFV ciphertext version)
 * @param X Input ciphertext vector (will be negated in-place)
 * @param evaluator Evaluator instance
 * @param decryptor Decryptor instance
 * @param relinkeys Relinization keys
 * @param k Size parameter
 * @param ZERO Encrypted zero
 * @param ONE Encrypted one
 * @return Encrypted D matrix
 */
vector<Ciphertext> getD(vector<Ciphertext>& X, Evaluator& evaluator, Decryptor& decryptor, RelinKeys relinkeys, int k, Ciphertext& ZERO, Ciphertext& ONE);

/**
 * @brief Compute difference polynomial coefficients (CKKS version)
 * @param X Input ciphertext vector (will be negated in-place)
 * @param evaluator Evaluator instance
 * @param decryptor Decryptor instance
 * @param relinkeys Relinization keys
 * @param k Size parameter
 * @param ZERO Encrypted zero
 * @param ONES Vector of encrypted ones at different levels
 * @param context SEAL context
 * @return Encrypted D matrix
 */
vector<Ciphertext> getDCKKS(vector<Ciphertext>& X, Evaluator& evaluator, Decryptor& decryptor, RelinKeys relinkeys, int k, Ciphertext& ZERO, vector<Ciphertext>& ONES, shared_ptr<SEALContext>& context);

/**
 * @brief Compute difference polynomial coefficients (BFV batch version)
 * @param X Input ciphertext vector
 * @param evaluator Evaluator instance
 * @param decryptor Decryptor instance
 * @param relinkeys Relinization keys
 * @param k Size parameter
 * @param ZERO Encrypted zero
 * @param ONES Encrypted one
 * @return Encrypted D matrix
 */
vector<Ciphertext> getDBFV(vector<Ciphertext>& X, Evaluator& evaluator, Decryptor& decryptor, RelinKeys relinkeys, int k, Ciphertext& ZERO, Ciphertext ONES);

/**
 * @brief Power of ciphertext (with noise checking)
 * @param evaluator Evaluator instance
 * @param baseTE Base ciphertext
 * @param decryptor Decryptor instance
 * @param mi Exponent
 * @param ONE Encrypted one
 * @param relinkeys Relinization keys
 * @return baseTE^mi
 */
Ciphertext mypow(Evaluator& evaluator, Ciphertext baseTE, Decryptor& decryptor, int mi, Ciphertext ONE, RelinKeys relinkeys);