/**
 * @file cipherProcess.h
 * @brief FHE-based secret sharing functions for BFV and CKKS schemes
 * @details Provides encrypted secret sharing and recovery functions using Microsoft SEAL library.
 *          Supports BFV (single integer and batch), CKKS, and hybrid encryption schemes.
 * @version 1.0
 * @date 2026
 */

#pragma once
#include "baseClass.h"
#include "SealSchme.h"
#include <seal/seal.h>

/**
 * @brief Encode and encrypt a single integer value (BFV)
 * @details Creates a plaintext from a single int64 value and encrypts it using BFV scheme
 * @param val Integer value to encrypt
 * @param enc Batch encoder
 * @param encryptor Encryptor instance
 * @return Encrypted ciphertext
 */
inline seal::Ciphertext encode_encrypt_int(std::int64_t val,
                                           const seal::BatchEncoder& enc,
                                           seal::Encryptor& encryptor)
{
    seal::Plaintext pt;
    enc.encode(std::vector<std::int64_t>{val}, pt);
    seal::Ciphertext ct;
    encryptor.encrypt(pt, ct);
    return ct;
}

/**
 * @brief Generate secret shares using BFV encryption (single integer version)
 * @details Implements (k, n) threshold secret sharing where each share is encrypted
 *          using the BFV scheme. Uses polynomial evaluation over encrypted data.
 * @param poly_modulus_degree Polynomial modulus degree
 * @param plain_mod Plain modulus
 * @param source Source picture containing secret data
 * @param shares Vector of SharePic objects to store generated shares
 * @param parms Scheme parameters
 * @param finalRes Result object to store timing information
 * @param printAns Whether to print generated shares
 */
inline void getShareByHE(std::size_t poly_modulus_degree,
                         std::uint16_t plain_mod,
                         Picture& source,
                         std::vector<SharePic>& shares,
                         Params& parms,
                         Result& finalRes,
                         bool printAns = true)
{
    std::cout << "Start to generate secret shares by FHE(BFV):\n";

    seal::EncryptionParameters seal_parms(seal::scheme_type::bfv);
    seal_parms.set_poly_modulus_degree(poly_modulus_degree);
    seal_parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    seal_parms.set_plain_modulus(plain_mod);

    auto ctx = std::make_shared<seal::SEALContext>(seal_parms, true, sec_level_type::none);
    seal::KeyGenerator keygen(*ctx);
    seal::PublicKey pk;
    keygen.create_public_key(pk);
    seal::SecretKey sk = keygen.secret_key();
    seal::RelinKeys rlk;
    keygen.create_relin_keys(rlk);

    seal::Encryptor encryptor(*ctx, pk, sk);
    seal::Evaluator evaluator(*ctx);
    seal::Decryptor decryptor(*ctx, sk);
    seal::BatchEncoder batch_enc(*ctx);

    std::vector<ll> y = source.getSec();
    std::cout << "encoding original Pictures:\n";
    clock_t st = clock();
    for (ll v : y) source.pushCipher(encode_encrypt_int(v, batch_enc, encryptor));
    auto pix_en = source.getSecEn();

    for (auto& sh : shares)
        for (ll xv : sh.getX())
            sh.x_en.push_back(encode_encrypt_int(xv, batch_enc, encryptor));

    clock_t end = clock();
    double dur = static_cast<double>(end - st) / CLOCKS_PER_SEC;
    finalRes.encode0 = dur;
    std::cout << "encoding finished. time: " << dur << "s\n\n";

    std::cout << "generate Shares beginning:\n";
    st = clock();
    for (std::size_t idx = 0; idx * parms.getk() < y.size(); ++idx) {
        std::vector<seal::Ciphertext> temy;
        for (int i = 0; i < parms.getk(); ++i)
            temy.push_back(pix_en[idx * parms.getk() + i]);
        for (auto& sh : shares) sh.addNewPixByCipher(temy, evaluator, rlk, idx);
    }
    end = clock();
    dur = static_cast<double>(end - st) / CLOCKS_PER_SEC;
    finalRes.generate0 = dur;
    std::cout << "Shares generated. time: " << dur << "s\n\n";

    std::cout << "decoding shares:\n";
    st = clock();
    for (std::size_t i = 0; i < shares.size(); ++i) {
        if (printAns) std::cout << "the " << i << "th shares' pixes are:";
        shares[i].showShareBFV(decryptor, batch_enc, printAns);
    }
    end = clock();
    dur = static_cast<double>(end - st) / CLOCKS_PER_SEC;
    finalRes.decode0 = dur;
    std::cout << "decoding finished. time: " << dur << "s\n\n";
}

/**
 * @brief Recover secret picture from BFV encrypted shares (single integer version)
 * @details Reconstructs the original secret using encrypted shares via Lagrange interpolation
 * @param picParms Scheme parameters
 * @param uploadShares Vector of encrypted shares
 * @param tools Decryption tools containing intermediate values
 * @param finalRes Result object to store timing information
 * @param degree Polynomial modulus degree (default: 8192)
 * @param plain_mod Plain modulus (default: 1024)
 * @param printAns Whether to print recovery results
 * @return Recovered picture
 */
inline Picture recoryShare(Params& picParms,
                           std::vector<SharePic> uploadShares,
                           DecTools& tools,
                           Result& finalRes,
                           std::size_t degree = 8192,
                           std::uint16_t plain_mod = 1024,
                           bool printAns = true)
{
    std::cout << "--------------------------------------------\n"
                 "Start Fully recovery the pic by FHE;\n"
                 "Generate the scheme base information:\n";
    seal::EncryptionParameters seal_parms(seal::scheme_type::bfv);
    seal_parms.set_poly_modulus_degree(degree);
    seal_parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(degree));
    seal_parms.set_plain_modulus(plain_mod);

    auto ctx = std::make_shared<seal::SEALContext>(seal_parms, true, sec_level_type::none);
    seal::KeyGenerator keygen(*ctx);
    seal::PublicKey pk;
    keygen.create_public_key(pk);
    seal::SecretKey sk = keygen.secret_key();
    seal::RelinKeys rlk;
    keygen.create_relin_keys(rlk);

    seal::Encryptor encryptor(*ctx, pk, sk);
    seal::Evaluator evaluator(*ctx);
    seal::Decryptor decryptor(*ctx, sk);
    seal::BatchEncoder batch_enc(*ctx);

    /* 本地重新加密 */
    std::cout << "Start to encode the local shares:\nwaiting....\n";
    clock_t start = clock();
    for (auto& sh : uploadShares)
        for (size_t j = 0; j < sh.X.size(); ++j) {
            sh.x_en[j] = encode_encrypt_int(sh.X[j], batch_enc, encryptor);
            sh.fx_en[j] = encode_encrypt_int(sh.fx[j], batch_enc, encryptor);
        }
    clock_t end = clock();
    double dur = static_cast<double>(end - start) / CLOCKS_PER_SEC;
    finalRes.encode1 = dur;
    std::cout << "encoding finished. time: " << dur << "s\n\n";

    Norm norm(batch_enc, encryptor, picParms);
    Picture recon_pic(picParms);
    std::cout << "Start reconstructing Pics procedure:\n";
    start = clock();
    for (int group = 0; group < static_cast<int>(uploadShares[0].X.size()); ++group) {
        std::vector<seal::Ciphertext> X, Ys;
        for (auto& sh : uploadShares) {
            X.push_back(sh.x_en[group]);
            Ys.push_back(sh.fx_en[group]);
        }
        seal::Ciphertext invKT = encode_encrypt_int(tools.invKT[group], batch_enc, encryptor);

        std::vector<seal::Ciphertext> a =
            fullRecovery(X, Ys, invKT, encryptor, evaluator,
                         batch_enc, decryptor, rlk, norm, picParms.getk());
        for (auto& c : a) recon_pic.pushCipher(c);
    }
    end = clock();
    dur = static_cast<double>(end - start) / CLOCKS_PER_SEC;
    std::cout << "reconstructing finished. time: " << dur << "s\n";
    finalRes.generate1 = dur;

    recon_pic.setPic(recon_pic.DecryPicBFV(decryptor, batch_enc, evaluator, norm, finalRes, printAns));
    return recon_pic;
}

/**
 * @brief Generate secret shares using CKKS encryption
 * @details Implements (k, n) threshold secret sharing using CKKS scheme for floating-point data
 * @param poly_modulus_degree Polynomial modulus degree
 * @param source Source picture containing secret data
 * @param shares Vector of SharePic objects to store generated shares
 * @param parms Scheme parameters
 * @param finalRes Result object to store timing information
 * @param printAns Whether to print generated shares
 */
inline void getShareByCKKS(std::size_t poly_modulus_degree,
                           Picture& source,
                           std::vector<SharePic>& shares,
                           Params& parms,
                           Result& finalRes,
                           bool printAns = true)
{
    std::cout << "Start to generate secret shares by FHE(CKKS):\n";
    seal::EncryptionParameters seal_parms(seal::scheme_type::ckks);
    seal_parms.set_poly_modulus_degree(poly_modulus_degree);

    std::vector<int> bit_sizes(parms.getMaxLevel() + 2, parms.getBaseLenOfModulus());
    bit_sizes.front() = bit_sizes.back() = std::min(parms.getBaseLenOfModulus() + 20, 60);
    seal_parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, bit_sizes));

    auto ctx = std::make_shared<seal::SEALContext>(seal_parms, true, sec_level_type::none);
    seal::KeyGenerator keygen(*ctx);
    seal::PublicKey pk;
    keygen.create_public_key(pk);
    seal::SecretKey sk = keygen.secret_key();
    seal::RelinKeys rlk;
    keygen.create_relin_keys(rlk);

    seal::Encryptor encryptor(*ctx, pk, sk);
    seal::Evaluator evaluator(*ctx);
    seal::Decryptor decryptor(*ctx, sk);
    seal::CKKSEncoder encoder(*ctx);

    std::vector<double> y = source.getSecFromDouble();
    const int K = parms.getk();
    if (y.size() % K) y.resize(y.size() - y.size() % K + K);

    std::vector<std::vector<double>> pixes(K);
    for (std::size_t i = 0; i < y.size(); ++i) pixes[i % K].push_back(y[i]);

    std::cout << "encoding original Pictures:\n";
    clock_t st = clock();
    size_t slot_count = encoder.slot_count();
    size_t x_size = pixes[0].size();
    seal::Plaintext y_plain;
    seal::Ciphertext y_en;
    for (int i = 0; i < K; ++i) {
        encoder.encode(pixes[i], parms.getScale(), y_plain);
        encryptor.encrypt(y_plain, y_en);
        source.pushCipher(y_en);
    }
    auto pixes_en = source.getSecEn();

    for (std::size_t i = 0; i < shares.size(); ++i) {
        std::vector<double> Xvec(slot_count, 0.0);
        for (size_t j = 0; j < x_size; ++j) {
            Xvec[j] = static_cast<double>(shares[i].X[0]);
        }
        seal::Plaintext pt;
        seal::Ciphertext ct;
        encoder.encode(Xvec, parms.getScale(), pt);
        encryptor.encrypt(pt, ct);
        shares[i].x_en.push_back(ct);
    }
    clock_t end = clock();
    double dur = static_cast<double>(end - st) / CLOCKS_PER_SEC;
    finalRes.encode0 = dur;
    std::cout << "encoding finished. time: " << dur << "s\n\n";

    std::cout << "generate Shares beginning:\n";
    st = clock();
    Norm norm(encoder, encryptor, evaluator, rlk, parms);
    for (auto& sh : shares)
        sh.generateCKKSShares(pixes_en, evaluator, rlk, ctx, norm.ONES);
    end = clock();
    dur = static_cast<double>(end - st) / CLOCKS_PER_SEC;
    finalRes.generate0 = dur;
    std::cout << "Shares generated. time: " << dur << "s\n\n";

    std::cout << "decoding shares:\n";
    st = clock();
    for (std::size_t i = 0; i < shares.size(); ++i) {
        if (printAns) std::cout << "the " << i << "th shares' pixes are:";
        shares[i].showShareCKKS(decryptor, encoder, printAns);
    }
    end = clock();
    dur = static_cast<double>(end - st) / CLOCKS_PER_SEC;
    finalRes.decode0 = dur;
    std::cout << "decoding finished. time: " << dur << "s\n\n";
}

/**
 * @brief Recover secret picture from CKKS encrypted shares
 * @details Reconstructs the original secret using encrypted CKKS shares via Lagrange interpolation
 * @param picParms Scheme parameters
 * @param uploadShares Vector of encrypted shares
 * @param tools Decryption tools containing intermediate values
 * @param finalRes Result object to store timing information
 * @param oriPic Original picture for comparison
 * @param degree Polynomial modulus degree (default: 8192)
 * @param printAns Whether to print recovery results
 * @return Recovered picture
 */
inline Picture recoryShareCKKS(Params& picParms,
                               std::vector<SharePic>& uploadShares,
                               DecTools& tools,
                               Result& finalRes,
                               Picture& oriPic,
                               std::size_t degree = 8192,
                               bool printAns = true)
{
    std::cout << "--------------------------------------------\n"
                 "Start Fully recovery the pic by FHE(CKKS);\n"
                 "Generate the scheme base information:\n";
    seal::EncryptionParameters seal_parms(seal::scheme_type::ckks);
    seal_parms.set_poly_modulus_degree(degree);

    std::vector<int> bit_sizes(picParms.getMaxLevel() + 2, picParms.getBaseLenOfModulus());
    bit_sizes.front() = bit_sizes.back() = std::min(picParms.getBaseLenOfModulus() + 20, 60);
    seal_parms.set_coeff_modulus(seal::CoeffModulus::Create(degree, bit_sizes));

    auto ctx = std::make_shared<seal::SEALContext>(seal_parms, true, sec_level_type::none);
    seal::KeyGenerator keygen(*ctx);
    seal::PublicKey pk;
    keygen.create_public_key(pk);
    seal::SecretKey sk = keygen.secret_key();
    seal::RelinKeys rlk;
    keygen.create_relin_keys(rlk);

    seal::Encryptor encryptor(*ctx, pk, sk);
    seal::Evaluator evaluator(*ctx);
    seal::Decryptor decryptor(*ctx, sk);
    seal::CKKSEncoder encoder(*ctx);

    /* 本地重新加密 */
    std::cout << "Start to encode the local shares:\nwaiting....\n";
    clock_t start = clock();
    size_t slot_count = encoder.slot_count();
    size_t x_size = uploadShares[0].fx.size();
    for (auto& sh : uploadShares) {
        // 重新加密 x，铺满有效 slot
        std::vector<double> Xvec(slot_count, 0.0);
        for (size_t j = 0; j < x_size; ++j) {
            Xvec[j] = static_cast<double>(sh.X[0]);
        }
        seal::Plaintext x_pt;
        encoder.encode(Xvec, picParms.getScale(), x_pt);
        if (sh.x_en.empty()) sh.x_en.emplace_back();
        encryptor.encrypt(x_pt, sh.x_en[0]);

        // 重新加密 fx，铺满有效 slot
        std::vector<double> Yvec(slot_count, 0.0);
        for (size_t j = 0; j < sh.fx.size(); ++j) {
            Yvec[j] = static_cast<double>(sh.fx[j]);
        }
        seal::Plaintext y_pt;
        encoder.encode(Yvec, picParms.getScale(), y_pt);
        if (sh.fx_en.empty()) sh.fx_en.emplace_back();
        encryptor.encrypt(y_pt, sh.fx_en[0]);
    }
    clock_t end = clock();
    double dur = static_cast<double>(end - start) / CLOCKS_PER_SEC;
    finalRes.encode1 = dur;
    std::cout << "encoding finished. time: " << dur << "s\n\n";

    Norm norm(encoder, encryptor, evaluator, rlk, picParms);
    Picture recon_pic(picParms);
    std::cout << "Start reconstructing Pics procedure:\n";
    start = clock();
    for (size_t group = 0; group < uploadShares[0].fx.size(); ++group) {
        std::vector<seal::Ciphertext> X, Ys;
        for (auto& sh : uploadShares) {
            X.push_back(sh.x_en[0]);
            Ys.push_back(sh.fx_en[0]);
        }
        
        std::vector<double> invKT_vec(slot_count, 0.0);
        for (size_t j = 0; j < x_size; ++j) {
            invKT_vec[j] = static_cast<double>(tools.invKT[group]);
        }
        seal::Plaintext invKT_plain;
        encoder.encode(invKT_vec, picParms.getScale(), invKT_plain);
        seal::Ciphertext invKT_en;
        encryptor.encrypt(invKT_plain, invKT_en);

        std::vector<seal::Ciphertext> a =
            fullRecoveryCKKS(X, Ys, invKT_en, encryptor, evaluator,
                             encoder, decryptor, rlk, norm, picParms, ctx);
        for (auto& c : a) recon_pic.pushCipher(c);
    }
    end = clock();
    dur = static_cast<double>(end - start) / CLOCKS_PER_SEC;
    std::cout << "reconstructing finished. time: " << dur << "s\n";
    finalRes.generate1 = dur;

    recon_pic.setPic(recon_pic.DecryPicCKKS(decryptor, encoder, evaluator, norm, finalRes, printAns));
    recon_pic.compare(oriPic, norm);
    return recon_pic;
}

/**
 * @brief Generate secret shares using BFV batch encryption
 * @details Implements (k, n) threshold secret sharing using BFV batching for parallel processing
 * @param poly_modulus_degree Polynomial modulus degree
 * @param source Source picture containing secret data
 * @param shares Vector of SharePic objects to store generated shares
 * @param parms Scheme parameters
 * @param finalRes Result object to store timing information
 * @param printAns Whether to print generated shares
 */
inline void getShareByBFV(std::size_t poly_modulus_degree,
                          Picture& source,
                          std::vector<SharePic>& shares,
                          Params& parms,
                          Result& finalRes,
                          bool printAns = true)
{
    std::cout << "Start to generate secret shares by FHE(BFV-batch):\n";
    seal::EncryptionParameters seal_parms(seal::scheme_type::bfv);
    seal_parms.set_poly_modulus_degree(poly_modulus_degree);
    seal_parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    seal_parms.set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, 40));

    auto context = std::make_shared<seal::SEALContext>(seal_parms, true, sec_level_type::none);
    seal::KeyGenerator keygen(*context);
    seal::PublicKey pk;
    keygen.create_public_key(pk);
    seal::SecretKey sk = keygen.secret_key();
    seal::RelinKeys rlk;
    keygen.create_relin_keys(rlk);

    seal::Encryptor encryptor(*context, pk, sk);
    seal::Evaluator evaluator(*context);
    seal::Decryptor decryptor(*context, sk);
    seal::BatchEncoder encoder(*context);

    std::vector<double> y = source.getSecFromDouble();
    const int K = parms.getk();
    if (y.size() % K) y.resize(y.size() - y.size() % K + K);

    const std::size_t slot_count = encoder.slot_count();
    std::vector<std::vector<std::int64_t>> pixes(K, std::vector<std::int64_t>(slot_count, 0));
    int x_size = 0;
    for (std::size_t i = 0; i < y.size(); ++i) {
        pixes[i % K][x_size] = static_cast<std::int64_t>(y[i]);
        if (i % K == K - 1) ++x_size;
    }
    for (int i = 0; i < K; ++i) pixes[i].resize(slot_count);

    std::cout << "encoding original Pictures:\n";
    clock_t st = clock();
    seal::Plaintext y_plain;
    seal::Ciphertext y_en;
    for (int i = 0; i < K; ++i) {
        encoder.encode(pixes[i], y_plain);
        encryptor.encrypt(y_plain, y_en);
        source.pushCipher(y_en);
    }
    auto pixes_en = source.getSecEn();

    seal::Plaintext tem1;
    seal::Ciphertext tem2;
    std::vector<std::int64_t> X(slot_count, 0);
    for (std::size_t i = 0; i < shares.size(); ++i) {
        std::fill(X.begin(), X.begin() + x_size, shares[i].X[0]);
        encoder.encode(X, tem1);
        encryptor.encrypt(tem1, tem2);
        shares[i].x_en.push_back(tem2);
    }
    clock_t end = clock();
    double dur = static_cast<double>(end - st) / CLOCKS_PER_SEC;
    finalRes.encode0 = dur;
    std::cout << "encoding finished. time: " << dur << "s\n\n";

    std::cout << "generate Shares beginning:\n";
    st = clock();
    Norm norm(encoder, encryptor, evaluator, rlk, parms);
    for (auto& sh : shares)
        sh.generateBFVShares(pixes_en, evaluator, rlk, context, norm.one_en);
    end = clock();
    dur = static_cast<double>(end - st) / CLOCKS_PER_SEC;
    finalRes.generate0 = dur;
    std::cout << "Shares generated. time: " << dur << "s\n\n";

    std::cout << "decoding shares:\n";
    st = clock();
    for (std::size_t i = 0; i < shares.size(); ++i) {
        if (printAns) std::cout << "the " << i << "th shares' pixes are:";
        shares[i].showShareBFV(decryptor, encoder, printAns);
    }
    end = clock();
    dur = static_cast<double>(end - st) / CLOCKS_PER_SEC;
    finalRes.decode0 = dur;
    std::cout << "decoding finished. time: " << dur << "s\n\n";
}

/**
 * @brief Recover secret picture from BFV batch encrypted shares
 * @details Reconstructs the original secret using encrypted BFV batch shares via Lagrange interpolation
 * @param picParms Scheme parameters
 * @param uploadShares Vector of encrypted shares
 * @param tools Decryption tools containing intermediate values
 * @param finalRes Result object to store timing information
 * @param oriPic Original picture for comparison
 * @param degree Polynomial modulus degree (default: 8192)
 * @param printAns Whether to print recovery results
 * @return Recovered picture
 */
inline Picture recoryShareBFV(Params& picParms,
                              std::vector<SharePic>& uploadShares,
                              DecTools& tools,
                              Result& finalRes,
                              Picture& oriPic,
                              std::size_t degree = 8192,
                              bool printAns = true)
{
    std::cout << "--------------------------------------------\n"
                 "Start Fully recovery the pic by FHE(batch BFV);\n"
                 "Generate the scheme base information:\n";
    seal::EncryptionParameters seal_parms(seal::scheme_type::bfv);
    seal_parms.set_poly_modulus_degree(degree);
    seal_parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(degree));
    seal_parms.set_plain_modulus(seal::PlainModulus::Batching(degree, 40));

    auto context = std::make_shared<seal::SEALContext>(seal_parms, true, sec_level_type::none);
    seal::KeyGenerator keygen(*context);
    seal::PublicKey pk;
    keygen.create_public_key(pk);
    seal::SecretKey sk = keygen.secret_key();
    seal::RelinKeys rlk;
    keygen.create_relin_keys(rlk);

    seal::Encryptor encryptor(*context, pk, sk);
    seal::Evaluator evaluator(*context);
    seal::Decryptor decryptor(*context, sk);
    seal::BatchEncoder encoder(*context);

    /* 本地重新加密 */
    std::cout << "Start to encode the local shares:\nwaiting....\n";
    clock_t start = clock();
    const std::size_t slot_count = encoder.slot_count();
    std::vector<std::int64_t> Xtem(slot_count, 0), Ytem(slot_count, 0);
    for (auto& sh : uploadShares) {
        std::fill(Xtem.begin(), Xtem.end(), sh.X[0]);
        seal::Plaintext pt;
        encoder.encode(Xtem, pt);
        encryptor.encrypt(pt, sh.x_en[0]);

        std::fill(Ytem.begin(), Ytem.end(), 0);
        for (size_t j = 0; j < sh.fx.size(); ++j) Ytem[j] = sh.fx[j];
        encoder.encode(Ytem, pt);
        encryptor.encrypt(pt, sh.fx_en[0]);
    }
    clock_t end = clock();
    double dur = static_cast<double>(end - start) / CLOCKS_PER_SEC;
    finalRes.encode1 = dur;
    std::cout << "encoding finished. time: " << dur << "s\n\n";

    /* 构造 Norm & 逐组恢复 */
    Norm norm(encoder, encryptor, evaluator, rlk, picParms);
    Picture recon_pic(picParms);
    std::cout << "Start reconstructing Pics procedure:\n";
    start = clock();
    for (size_t group = 0; group < uploadShares[0].fx.size(); ++group) {
        std::vector<seal::Ciphertext> X, Ys;
        for (auto& sh : uploadShares) {
            X.push_back(sh.x_en[group]);
            Ys.push_back(sh.fx_en[group]);
        }
        std::vector<std::int64_t> invK(slot_count, tools.invKT[group]);
        seal::Plaintext invKT_plain;
        encoder.encode(invK, invKT_plain);
        seal::Ciphertext invKT_en;
        encryptor.encrypt(invKT_plain, invKT_en);

        std::vector<seal::Ciphertext> a =
            fullRecoveryBFV(X, Ys, invKT_en, encryptor, evaluator,
                            encoder, decryptor, rlk, norm, picParms, context);
        for (auto& c : a) recon_pic.pushCipher(c);
    }
    end = clock();
    dur = static_cast<double>(end - start) / CLOCKS_PER_SEC;
    std::cout << "reconstructing finished. time: " << dur << "s\n";
    finalRes.generate1 = dur;

    recon_pic.setPic(recon_pic.DecryPicBFV(decryptor, encoder, evaluator, norm, finalRes, printAns));
    recon_pic.compare(oriPic, norm);
    return recon_pic;
}