/**
 * @file PlainProcess.h
 * @brief Plaintext processing functions for secret sharing
 * @details Provides functions for generating and recovering secret shares using plaintext operations
 * @version 1.0
 * @date 2026
 */

#pragma once
#include"baseClass.h"
using namespace std;

/**
 * @brief Generate secret shares using plaintext polynomial evaluation
 * @details Implements (k, n) threshold secret sharing using Lagrange interpolation
 *          Each share is a point (x, f(x)) on a polynomial of degree k-1
 * @param source Source picture containing secret data
 * @param shares Vector of SharePic objects to store generated shares
 * @param k Threshold parameter (polynomial degree + 1)
 * @param range_x Range for random x values
 * @param printAns Whether to print generated shares
 */
void getShareByPlain(Picture& source, vector<SharePic>& shares, int k = 4, int range_x = 10, bool printAns = true);

/**
 * @brief Generate secret shares with common X values
 * @details All shares share the same x values but different polynomial evaluations
 * @param source Source picture containing secret data
 * @param shares Vector of SharePic objects to store generated shares
 * @param k Threshold parameter
 * @param range_x Range for random x values
 * @param printAns Whether to print generated shares
 */
void getShareByPlain_VEC(Picture& source, vector<SharePic>& shares, int k = 4, int range_x = 10, bool printAns = true);

/**
 * @brief Recover secret from shares using Lagrange interpolation
 * @details Reconstructs the original secret using k or more shares
 * @param Xtem Vector of x values from shares
 * @param ytem Vector of y values (f(x)) from shares
 * @param tools Decryption tools containing intermediate values
 * @param parms Scheme parameters
 * @param index Index for intermediate value storage
 * @return Recovered secret values
 */
vector<int> recoveryDemo(vector<int>& Xtem, vector<int>& ytem, DecTools& tools, Params& parms, int index);

/**
 * @brief Recover secret picture from plaintext shares
 * @param source Vector of SharePic objects
 * @param parms Scheme parameters
 * @param tools Decryption tools
 * @return Recovered Picture
 */
Picture recoveryByPlain(vector<SharePic>& source, Params& parms, DecTools& tools);

/**
 * @brief Recover secret picture from plaintext shares (CKKS variant)
 * @param source Vector of SharePic objects
 * @param parms Scheme parameters
 * @param tools Decryption tools
 * @return Recovered Picture
 */
Picture recoveryByPlainCKKS(vector<SharePic>& source, Params& parms, DecTools& tools);