#pragma once
#include <iostream>
#include <vector>
#include "seal/seal.h"
#include "mymath.h"
#include "tools.h"

/*==============================================================
 *  工具：打印上下文参数（4.1.2 版）
 *=============================================================*/
inline void print_parameters(std::shared_ptr<seal::SEALContext> context)
{
    if (!context) throw std::invalid_argument("context is not set");
    const auto& ctx_data = *context->key_context_data();

    std::string scheme_name;
    switch (ctx_data.parms().scheme()) {
    case seal::scheme_type::bfv: scheme_name = "BFV"; break;
    case seal::scheme_type::ckks: scheme_name = "CKKS"; break;
    default: throw std::invalid_argument("unsupported scheme");
    }

    std::cout << "/\n| Encryption parameters :\n";
    std::cout << "|   scheme: " << scheme_name << "\n";
    std::cout << "|   poly_modulus_degree: "
              << ctx_data.parms().poly_modulus_degree() << "\n";

    std::cout << "|   coeff_modulus size: "
              << ctx_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_mod = ctx_data.parms().coeff_modulus();
    for (size_t i = 0; i + 1 < coeff_mod.size(); ++i)
        std::cout << coeff_mod[i].bit_count() << " + ";
    std::cout << coeff_mod.back().bit_count() << ") bits\n";

    if (ctx_data.parms().scheme() == seal::scheme_type::bfv)
        std::cout << "|   plain_modulus: "
                  << ctx_data.parms().plain_modulus().value() << "\n";
    std::cout << "\\\n";
}

/*==============================================================
 *  工具：噪声预算
 *=============================================================*/
inline void getNoise(seal::Decryptor& decryptor, const seal::Ciphertext& ct)
{
    std::cout << "Noise budget: " << decryptor.invariant_noise_budget(ct) << " bits\n";
}

/*==============================================================
 *  工具：BFV 单整数加密（4.1.2 版）
 *=============================================================*/
inline seal::Ciphertext getEnText(std::int64_t value,
                                  seal::BatchEncoder& encoder,
                                  seal::Encryptor& encryptor)
{
    seal::Plaintext pt;
    encoder.encode(std::vector<std::int64_t>{value}, pt);
    seal::Ciphertext ct;
    encryptor.encrypt(pt, ct);
    return ct;
}

inline std::vector<seal::Ciphertext>
getEnText(const std::vector<std::int64_t>& values,
          seal::BatchEncoder& encoder,
          seal::Encryptor& encryptor)
{
    std::vector<seal::Ciphertext> ans;
    ans.reserve(values.size());
    for (auto v : values) ans.push_back(getEnText(v, encoder, encryptor));
    return ans;
}

/*==============================================================
 *  工具：CKKS 单 double 加密
 *=============================================================*/
inline seal::Ciphertext
getEnText(double value, double scale,
          seal::CKKSEncoder& encoder,
          seal::Encryptor& encryptor)
{
    seal::Plaintext pt;
    encoder.encode(std::vector<double>{value}, scale, pt);
    seal::Ciphertext ct;
    encryptor.encrypt(pt, ct);
    return ct;
}

/*==============================================================
 *  工具：BFV 解密单个 int64
 *=============================================================*/
inline std::int64_t
getDeText(seal::Decryptor& decryptor,
          seal::BatchEncoder& encoder,
          const seal::Ciphertext& ct)
{
    seal::Plaintext pt;
    decryptor.decrypt(ct, pt);
    std::vector<std::int64_t> vec;
    encoder.decode(pt, vec);
    return vec.empty() ? 0 : vec[0];
}

/*==============================================================
 *  工具：CKKS 解密单个 double
 *=============================================================*/
inline double
getDeText(seal::Decryptor& decryptor,
          seal::CKKSEncoder& encoder,
          const seal::Ciphertext& ct)
{
    seal::Plaintext pt;
    decryptor.decrypt(ct, pt);
    std::vector<double> vec;
    encoder.decode(pt, vec);
    return vec.empty() ? 0.0 : vec[0];
}

/*==============================================================
 *  工具：快速检查噪声
 *=============================================================*/
inline void check(seal::Decryptor& decryptor, const seal::Ciphertext& ct)
{
    if (decryptor.invariant_noise_budget(ct) == 0) {
        std::cout << "noise is out of range!\n";
        std::exit(0);
    }
}

/*==============================================================
 *  工具：打印 BFV 明文（调试用）
 *=============================================================*/
inline void printDe(seal::Decryptor& decryptor,
                    seal::BatchEncoder& encoder,
                    const seal::Ciphertext& ct)
{
    seal::Plaintext pt;
    decryptor.decrypt(ct, pt);
    std::vector<std::int64_t> v;
    encoder.decode(pt, v);
    for (auto x : v) std::cout << x << " ";
    std::cout << "\n";
}

/*==============================================================
 *  工具：打印 CKKS 明文（调试用）
 *=============================================================*/
inline void printDe(seal::Decryptor& decryptor,
                    seal::CKKSEncoder& encoder,
                    const seal::Ciphertext& ct,
                    size_t print_cnt = 8)
{
    seal::Plaintext pt;
    decryptor.decrypt(ct, pt);
    std::vector<double> v;
    encoder.decode(pt, v);
    for (size_t i = 0; i < std::min(print_cnt, v.size()); ++i)
        std::cout << v[i] << " ";
    std::cout << "\n";
}

/*==============================================================
 *  计算拉格朗日系数 m_i = 1 / \prod_{j≠i}(x_i - x_j)   (BFV)
 *=============================================================*/
inline std::vector<seal::Ciphertext>
getM(seal::Evaluator& evaluator,
     seal::RelinKeys& relin_keys,
     const std::vector<seal::Ciphertext>& X,
     const seal::Ciphertext& ONE,
     seal::Decryptor& decryptor,
     seal::Ciphertext& KT,        // 乘积累加器（可就地更新）
     seal::BatchEncoder& encoder)
{
    std::vector<seal::Ciphertext> M;
    M.reserve(X.size());
    for (size_t i = 0; i < X.size(); ++i) {
        seal::Ciphertext prod = ONE;
        for (size_t j = 0; j < X.size(); ++j) {
            if (i == j) continue;
            seal::Ciphertext tmp;
            evaluator.sub(X[i], X[j], tmp);
            evaluator.multiply_inplace(prod, tmp);
            evaluator.relinearize_inplace(prod, relin_keys);
        }
        M.push_back(prod);
        evaluator.multiply_inplace(KT, prod);
        evaluator.relinearize_inplace(KT, relin_keys);
        check(decryptor, KT);
    }
    return M;
}

/*==============================================================
 *  计算拉格朗日系数 m_i  (CKKS)
 *=============================================================*/
vector<Ciphertext> getMCKKS(Evaluator& evaluator, RelinKeys& relinkeys, vector<Ciphertext> X,
  vector<Ciphertext> ONES, Decryptor& decryptor, CKKSEncoder& encoder, shared_ptr<seal::SEALContext>& context) {
  vector<Ciphertext> M;
  vector<Ciphertext> temVec;
  Ciphertext tem1;
  for (int i = 0; i < X.size(); i++) {
    temVec.clear();
    for (int j = 0; j < X.size(); j++) {
      if (i == j)continue;
      evaluator.sub(X[i], X[j], tem1);
      temVec.push_back(tem1);
    }
    tem1 = cal_mut(temVec, evaluator, relinkeys, context, ONES);
    M.push_back(tem1);
  }
  return M;
}

/*==============================================================
 *  计算拉格朗日系数 m_i  (BFV-batch)
 *=============================================================*/
inline std::vector<seal::Ciphertext>
getMBFV(seal::Evaluator& evaluator,
        seal::RelinKeys& relin_keys,
        const std::vector<seal::Ciphertext>& X,
        const seal::Ciphertext& ONE,
        seal::Decryptor& decryptor,
        seal::BatchEncoder& encoder)
{
    std::vector<seal::Ciphertext> M;
    M.reserve(X.size());
    for (size_t i = 0; i < X.size(); ++i) {
        std::vector<seal::Ciphertext> tmp_vec;
        tmp_vec.reserve(X.size() - 1);
        for (size_t j = 0; j < X.size(); ++j) {
            if (i == j) continue;
            seal::Ciphertext t;
            evaluator.sub(X[i], X[j], t);
            tmp_vec.push_back(t);
        }
        seal::Ciphertext prod = tmp_vec[0];
        for (size_t j = 1; j < tmp_vec.size(); ++j) {
            evaluator.multiply_inplace(prod, tmp_vec[j]);
            evaluator.relinearize_inplace(prod, relin_keys);
        }
        M.push_back(prod);
    }
    return M;
}

/*==============================================================
 *  计算 K_i = \prod_{j≠i} m_j   (BFV)
 *=============================================================*/
inline std::vector<seal::Ciphertext>
getK(seal::Evaluator& evaluator,
     seal::RelinKeys& relin_keys,
     const std::vector<seal::Ciphertext>& m,
     const seal::Ciphertext& ONE,
     seal::Decryptor& decryptor,
     const seal::Ciphertext& P_se)
{
    std::vector<seal::Ciphertext> K;
    K.reserve(m.size());
    for (size_t i = 0; i < m.size(); ++i) {
        seal::Ciphertext prod = ONE;
        for (size_t j = 0; j < m.size(); ++j) {
            if (i == j) continue;
            evaluator.multiply_inplace(prod, m[j]);
            evaluator.relinearize_inplace(prod, relin_keys);
        }
        K.push_back(prod);
    }
    return K;
}

/*==============================================================
 *  计算 A_i = K_i * Y_i  (CKKS)
 *=============================================================*/
vector<Ciphertext> getACKKS(Evaluator& evaluator,
  RelinKeys& relinkeys,vector<Ciphertext>& Y,vector<Ciphertext>& m,
  vector<Ciphertext>& ONES, Decryptor& decryptor, shared_ptr<seal::SEALContext>& context) {//the decryptor is not necessary;
  vector<Ciphertext> A;
  vector<Ciphertext> temVec;
  Ciphertext tem;
  for (int i = 0; i < m.size(); i++) {
    temVec.clear();
    for (int j = 0; j < m.size(); j++) {
      if (i == j) continue;
      temVec.push_back(m[j]);
    }
    temVec.push_back(Y[i]);
    tem = cal_mut(temVec, evaluator, relinkeys, context, ONES);
    A.push_back(tem);
  }
  return A;
}

/*==============================================================
 *  计算 A_i = K_i * Y_i  (BFV-batch)
 *=============================================================*/
inline std::vector<seal::Ciphertext>
getABFV(seal::Evaluator& evaluator,
        seal::RelinKeys& relin_keys,
        const std::vector<seal::Ciphertext>& Y,
        const std::vector<seal::Ciphertext>& m,
        const seal::Ciphertext& ONE,
        seal::Decryptor& decryptor)
{
    std::vector<seal::Ciphertext> A;
    A.reserve(m.size());
    for (size_t i = 0; i < m.size(); ++i) {
        std::vector<seal::Ciphertext> tmp = { m[0] };
        for (size_t j = 1; j < m.size(); ++j)
            if (i != j) tmp.push_back(m[j]);
        tmp.push_back(Y[i]);
        seal::Ciphertext prod = tmp[0];
        for (size_t j = 1; j < tmp.size(); ++j) {
            evaluator.multiply_inplace(prod, tmp[j]);
            evaluator.relinearize_inplace(prod, relin_keys);
        }
        A.push_back(prod);
    }
    return A;
}

/*==============================================================
 *  遗留接口：recovery (BFV 单整数版) —— 仅做演示，已替换为 BatchEncoder
 *=============================================================*/
inline std::vector<int>
recovery(std::vector<long long>& X,
         std::vector<long long>& Y,
         std::vector<long long>& m,
         std::vector<long long>& K,
         long long KT, long long invKT,
         std::size_t poly_modulus_degree,
         std::uint16_t plain_mod,
         int k = 4)
{
    std::cout << "--------------------------------------------\n"
                 "Start recovery the pic by FHE (SEAL 4.1.2);\n"
                 "Generate the scheme base information:\n";

    /* 1. 构造 SEAL 4.1.2 参数对象 */
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(plain_mod);

    seal::SEALContext context(parms);                 // 4.1.2 直接构造
    seal::KeyGenerator keygen(context);
    seal::PublicKey pk;
    keygen.create_public_key(pk);                     // 4.1.2 两步走
    seal::SecretKey sk = keygen.secret_key();
    seal::RelinKeys rlk;
    keygen.create_relin_keys(rlk);                    // 4.1.2 两步走

    seal::Encryptor encryptor(context, pk, sk);       // 4.1.2 三参数构造
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, sk);
    seal::BatchEncoder batch_enc(context);            // 4.1.2 统一用 BatchEncoder

    /* 2. 加密输入 */
    auto encode_encrypt = [&](long long v) {
        seal::Plaintext pt;
        batch_enc.encode(std::vector<std::int64_t>{v}, pt);
        seal::Ciphertext ct;
        encryptor.encrypt(pt, ct);
        return ct;
    };

    std::vector<seal::Ciphertext> X_en, Y_en, m_en, K_en;
    for (auto v : X)   X_en.push_back(encode_encrypt(v));
    for (auto v : Y)   Y_en.push_back(encode_encrypt(v));
    for (auto v : m)   m_en.push_back(encode_encrypt(v));
    for (auto v : K)   K_en.push_back(encode_encrypt(v));
    auto KT_en    = encode_encrypt(KT);
    auto invKT_en = encode_encrypt(invKT);

    std::cout << "upload X,Y,K,m,KT,invKT to the remote server:\n";

    /* 3. A = K_i * Y_i */
    std::vector<seal::Ciphertext> A;
    for (size_t i = 0; i < K_en.size(); ++i) {
        seal::Ciphertext t;
        evaluator.multiply(K_en[i], Y_en[i], t);
        evaluator.relinearize_inplace(t, rlk);
        A.push_back(t);
    }

    /* 4. 计算 D = getD(X, k) 并加密 */
    auto zero_ct = encode_encrypt(0LL);
    auto one_ct  = encode_encrypt(1LL);
    // 4.1.2 版 getD 签名已统一，直接调用
    auto D = getD(X_en, evaluator, decryptor, rlk, k, zero_ct, one_ct);

    /* 5. 恢复多项式系数 a_i = (∑ A_j * D_{j,k-1-i}) * invKT */
    std::vector<seal::Ciphertext> a;
    for (int i = 0; i < k; ++i) {
        seal::Ciphertext tem = zero_ct;
        for (int j = 0; j < k; ++j) {
            seal::Ciphertext tmp;
            evaluator.multiply(A[j], D[j * k + k - 1 - i], tmp);
            evaluator.add_inplace(tem, tmp);
        }
        evaluator.relinearize_inplace(tem, rlk);
        evaluator.multiply_inplace(tem, invKT_en);
        evaluator.relinearize_inplace(tem, rlk);
        a.push_back(tem);
    }

    /* 6. 本地解密并取模 */
    std::cout << "download from the center server;\nstart to decoder locally\n";
    std::vector<int> ans_fl;
    long long mod = 251;
    for (auto& ct : a) {
        seal::Plaintext pt;
        decryptor.decrypt(ct, pt);
        std::vector<std::int64_t> v;
        batch_enc.decode(pt, v);
        long long val = v.empty() ? 0 : v[0];
        val = ((val % mod) + mod) % mod;
        ans_fl.push_back(static_cast<int>(val));
    }

    std::cout << "recovery result of pixes:\n";
    for (int v : ans_fl) std::cout << v << " ";
    std::cout << "\n";
    return ans_fl;
}

/*==============================================================
 *  fullRecovery 系列（BFV / CKKS / BFV-batch）
 *  以下接口已统一为 4.1.2 语法，可直接调用
 *=============================================================*/
inline std::vector<seal::Ciphertext>
fullRecovery(std::vector<seal::Ciphertext>& X_en,
             std::vector<seal::Ciphertext>& Y_en,
             seal::Ciphertext invKT_en,
             seal::Encryptor& encryptor,
             seal::Evaluator& evaluator,
             seal::BatchEncoder& encoder,
             seal::Decryptor& decryptor,
             seal::RelinKeys& relin_keys,
             class Norm& norm,
             int k = 4)
{
    auto zeros_en = norm.zeros_en;
    auto one_en   = norm.one_en;
    auto P_se     = norm.P_sen;

    auto KT_en = one_en;
    auto m_en  = getMBFV(evaluator, relin_keys, X_en, one_en, decryptor, encoder);
    auto K_en  = getK(evaluator, relin_keys, m_en, one_en, decryptor, P_se);
    auto A     = getABFV(evaluator, relin_keys, Y_en, K_en, one_en, decryptor);
    auto D     = getDBFV(X_en, evaluator, decryptor, relin_keys, k, zeros_en, one_en);

    std::vector<seal::Ciphertext> a;
    for (int i = 0; i < k; ++i) {
        seal::Ciphertext tem = zeros_en;
        for (int j = 0; j < k; ++j) {
            seal::Ciphertext tmp;
            evaluator.multiply(A[j], D[j * k + k - 1 - i], tmp);
            evaluator.add_inplace(tem, tmp);
        }
        evaluator.relinearize_inplace(tem, relin_keys);
        evaluator.multiply_inplace(tem, invKT_en);
        evaluator.relinearize_inplace(tem, relin_keys);
        a.push_back(tem);
    }
    return a;
}

inline std::vector<seal::Ciphertext>
fullRecoveryCKKS(std::vector<seal::Ciphertext>& X_en,
                 std::vector<seal::Ciphertext>& Y_en,
                 seal::Ciphertext invKT_en,
                 seal::Encryptor& encryptor,
                 seal::Evaluator& evaluator,
                 seal::CKKSEncoder& encoder,
                 seal::Decryptor& decryptor,
                 seal::RelinKeys& relin_keys,
                 class Norm& norm,
                 class Params& parms,
                 std::shared_ptr<seal::SEALContext> context)
{
    int k = parms.getk();
    auto zeros_en = norm.ZERO;
    auto ones     = norm.ONES;

    auto m_en = getMCKKS(evaluator, relin_keys, X_en, ones, decryptor, encoder, context);
    auto A    = getACKKS(evaluator, relin_keys, Y_en, m_en, ones, decryptor, context);
    auto D    = getDCKKS(X_en, evaluator, decryptor, relin_keys, k, zeros_en, ones, context);

    std::vector<seal::Ciphertext> a;
    for (int i = 0; i < k; ++i) {
        seal::Ciphertext tem = zeros_en;
        for (int j = 0; j < k; ++j) {
            seal::Ciphertext tmp =
                cal_mut({A[j], D[j * k + k - 1 - i]}, evaluator, relin_keys, context, ones);
            add(evaluator, tem, tmp, context);
        }
        tem = cal_mut1({tem, invKT_en}, evaluator, relin_keys, context, ones, decryptor, encoder);
        a.push_back(tem);
    }
    return a;
}

inline std::vector<seal::Ciphertext>
fullRecoveryBFV(std::vector<seal::Ciphertext>& X_en,
                std::vector<seal::Ciphertext>& Y_en,
                seal::Ciphertext invKT_en,
                seal::Encryptor& encryptor,
                seal::Evaluator& evaluator,
                seal::BatchEncoder& encoder,
                seal::Decryptor& decryptor,
                seal::RelinKeys& relin_keys,
                class Norm& norm,
                class Params& parms,
                std::shared_ptr<seal::SEALContext> context)
{
    int k = parms.getk();
    auto zeros_en = norm.ZERO;
    auto one_en   = norm.one_en;

    auto m_en = getMBFV(evaluator, relin_keys, X_en, one_en, decryptor, encoder);
    auto A    = getABFV(evaluator, relin_keys, Y_en, m_en, one_en, decryptor);
    auto D    = getDBFV(X_en, evaluator, decryptor, relin_keys, k, zeros_en, one_en);

    std::vector<seal::Ciphertext> a;
    for (int i = 0; i < k; ++i) {
        seal::Ciphertext tem = zeros_en;
        for (int j = 0; j < k; ++j) {
            seal::Ciphertext tmp;
            evaluator.multiply(A[j], D[j * k + k - 1 - i], tmp);
            evaluator.add_inplace(tem, tmp);
        }
        evaluator.relinearize_inplace(tem, relin_keys);
        evaluator.multiply_inplace(tem, invKT_en);
        evaluator.relinearize_inplace(tem, relin_keys);
        a.push_back(tem);
    }
    return a;
}

/*==============================================================
 *  CKKS 优化版：X 为明文 double，省去一次加密
 *=============================================================*/
inline std::vector<seal::Ciphertext>
fullRecoveryCKKS2(std::vector<double>& X,
                  std::vector<seal::Ciphertext>& Y_en,
                  seal::Ciphertext invKT_en,
                  seal::Encryptor& encryptor,
                  seal::Evaluator& evaluator,
                  seal::CKKSEncoder& encoder,
                  seal::Decryptor& decryptor,
                  seal::RelinKeys& relin_keys,
                  class Norm& norm,
                  class Params& parms,
                  std::shared_ptr<seal::SEALContext> context)
{
    int k = parms.getk();
    auto zeros_en = norm.ZERO;
    auto ones     = norm.ONES;
    double scale  = parms.getScale();

    /* 明文计算 m 和 D */
    std::vector<double> m(k, 1.0), D = getD(X, k);
    for (int i = 0; i < k; ++i)
        for (int j = 0; j < k; ++j)
            if (i != j) m[i] *= (X[i] - X[j]);
    for (auto& v : m) v = 1.0 / v;

    std::vector<seal::Ciphertext> a;
    for (int i = 0; i < k; ++i) {
        seal::Ciphertext tem = zeros_en;
        for (int j = 0; j < k; ++j) {
            seal::Plaintext pt;
            encoder.encode(m[j] * D[j * k + k - 1 - i], scale, pt);
            seal::Ciphertext coef;
            encryptor.encrypt(pt, coef);
            seal::Ciphertext tmp =
                cal_mut({Y_en[j], coef}, evaluator, relin_keys, context, ones);
            add(evaluator, tem, tmp, context);
        }
        a.push_back(tem);
    }
    return a;
}