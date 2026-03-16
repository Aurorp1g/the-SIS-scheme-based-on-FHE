#pragma once
#include "tools.h"
#include <fstream>
#include "mymath.h"
#include "math_test.h"

#define ll long long
using namespace std;
using namespace seal;   // 建议后续挪到 .cpp，这里保持原样

/*============================ Result ============================*/
class Result {
public:
    Result() = default;
    void writeResult(string filename = "result.txt") {
        fstream file(filename, ios::out | ios::app);
        file << l << "," << w << "," << t << "," << n << "," << p << "," << x_range << ",";
        file << poly_d0 << "," << plain_m0 << ",";
        file << poly_d1 << "," << plain_m1 << ",";
        file << encode0 << "," << generate0 << "," << decode0 << ",";
        file << encode1 << "," << generate1 << "," << decode1 << "," << correct << endl;
        file.close();
    }
    double encode0{}, generate0{}, decode0{};
    double encode1{}, generate1{}, decode1{};
    double correct{};
    int l{}, w{}, t{}, n{}, p{}, x_range{};
    int poly_d0{}, plain_m0{}, poly_d1{}, plain_m1{};
};

/*============================ Params ============================*/
class Params {
    friend class Picture;
    friend class SharePic;
    friend class DecTools;
public:
    Params() = default;
    Params(int l = 2, int w = 2, int p = 251, int n = 6, int k = 4, int x = 10) {
        L = l; W = w; ModP = p;
        this->n = n; this->k = k; rangeX = x;
        baseLenOfModulus = 40;
        batches = ((L * W % k == 0) ? L * W / k : (L * W - L * W % k + k) / k);
    }
    int* getSize() {
        static int siz[2] = { L, W };
        return siz;
    }
    int getP() const { return ModP; }
    void setP(int P) { ModP = P; }
    int getN() const { return n; }
    void setN(int n) { this->n = n; }
    int getk() const { return k; }
    void setK(int K) { k = K; }
    int getXrange() const { return rangeX; }
    void setXrange(int range) { rangeX = range; }
    void setMaxLevel(int x) { maxLevel = x; }
    int getMaxLevel() const { return maxLevel; }
    void setScale(double scale) { this->scale = scale; }
    double getScale() const { return scale; }
    int getBaseLenOfModulus() const { return baseLenOfModulus; }
    void setBaseLenOfModulus(int len) { baseLenOfModulus = len; }
    int getBatches() const { return batches; }
    void setBatch(int batches) { this->batches = batches; }

private:
    int L{}, W{};
    int ModP{};
    int n{}, k{}, batches{};
    int rangeX{};
    int maxLevel{};
    double scale{};
    int baseLenOfModulus{};
};

/*============================ Norm ============================*/
class Norm {
public:
    Norm() = default;

    /*----- BFV 单整数 -----*/
    Norm(BatchEncoder& encoder, Encryptor& encryptor, Params& parms) {
        modP = parms.getP();
        size_t slot_count = encoder.slot_count();
        vector<int64_t> ONE(slot_count, 1), ZERO(slot_count, 0), P(slot_count, modP);
        Plaintext one, zero, p_plain;
        encoder.encode(ONE, one);
        encoder.encode(ZERO, zero);
        encoder.encode(P, p_plain);
        encryptor.encrypt(one, one_en);
        encryptor.encrypt(zero, zeros_en);
        encryptor.encrypt(p_plain, P_sen);
    }

    /*----- CKKS -----*/
    Norm(CKKSEncoder& encoder, Encryptor& encryptor, Evaluator& evaluator,
         RelinKeys& relin_keys, Params& parms) {
        modP = parms.getP();
        Ciphertext tem;
        for (int i = 0; i <= parms.getMaxLevel(); ++i) ONES.emplace_back();
        Plaintext one, zero, p_plain;
        encoder.encode(1.0, parms.getScale(), one);
        encoder.encode(0.0, parms.getScale(), zero);
        encoder.encode(static_cast<double>(modP), parms.getScale(), p_plain);
        encryptor.encrypt(one, tem);
        encryptor.encrypt(zero, ZERO);
        encryptor.encrypt(p_plain, P_sen);
        for (int i = parms.getMaxLevel(); i >= 0; --i) {
            ONES[i] = tem;
            if (i != 0) {
                evaluator.multiply_inplace(tem, tem);
                evaluator.relinearize_inplace(tem, relin_keys);
                evaluator.rescale_to_next_inplace(tem);
            }
        }
    }

    /*----- BFV 批处理 -----*/
    Norm(BatchEncoder& encoder, Encryptor& encryptor, Evaluator& evaluator,
         RelinKeys& relin_keys, Params& parms) : 
         Norm(encoder, encryptor, parms) {}  // 委托给单整数版本

    seal::Ciphertext zeros_en, P_sen, one_en;
    vector<seal::Ciphertext> ONES;
    seal::Ciphertext ZERO;
    int modP{};
    Error virError, realError;
    vector<double> virErrorData, realErrorData;
    vector<int> realErrorIndex;
};

/*============================ Picture ============================*/
class Picture {
    friend class SharePic;
public:
    Picture() = default;
    explicit Picture(Params& parms) {
        siz[0] = parms.L; siz[1] = parms.W;
        origin_pic.resize(siz[0] * siz[1], 0);
        origin_sec.resize(siz[0] * siz[1], 0);
        aerfa.resize(siz[0] * siz[1], 0);
        batches = parms.getBatches();
    }

    vector<ll>& getSec() { return origin_sec; }
    vector<double> getSecFromDouble() {
        if (origin_secCKKS.empty()) {
            origin_secCKKS.reserve(origin_sec.size());
            for (auto v : origin_sec) origin_secCKKS.push_back(static_cast<double>(v));
        }
        return origin_secCKKS;
    }
    vector<Ciphertext> getSecEn() { return pic_en; }
    int* getSiz() { return siz; }

    void generatePic(Params& parms, int randRange = 1) {
        for (int i = 0; i < siz[0]; ++i)
            for (int j = 0; j < siz[1]; ++j) {
                int idx = i * parms.W + j;
                origin_pic[idx] = rand() % parms.ModP;
                aerfa[idx] = static_cast<ll>(rand() % randRange);
                origin_sec[idx] = aerfa[idx] * parms.ModP + origin_pic[idx];
            }
    }
    void PrintParms(vector<ll>& vec) {
        for (auto v : vec) cout << v << " "; 
        cout << endl;  // 单独一行，消除歧义
    }
    void pushCipher(const seal::Ciphertext& text) { pic_en.push_back(text); }
    void printPic() {
        for (auto v : origin_pic) cout << v << " ";
        cout << endl << endl;
    }
    void pushPies(ll pixes, int index) { origin_pic[index] = pixes; }

    /*----- BFV 解密 -----*/
    vector<int> DecryPicBFV(Decryptor& decryptor, BatchEncoder& encoder,
                            Evaluator& evaluator, Norm& norm, Result& finalRes,
                            bool printAns = true) {
        Plaintext text1;
        vector<Ciphertext> a = pic_en;
        vector<int64_t> temAns[10];
        vector<int> ans_fl;
        auto zeros_en = norm.zeros_en;
        cout << "download from  the center server;\n"
             << "\n\n\nstart to decoder locally\n";
        double dur;
        clock_t st = clock(), end;

        for (size_t i = 0; i < a.size(); ++i) {
            decryptor.decrypt(a[i], text1);
            encoder.decode(text1, temAns[i]);
        }
        origin_pic.clear();
        for (int i = 0; i < batches; ++i)
            for (size_t j = 0; j < a.size(); ++j) {
                ans_fl.push_back((around(temAns[j][i]) % norm.modP + norm.modP) % norm.modP);
                norm.virErrorData.push_back(around(temAns[j][i]) - temAns[j][i]);
            }
        end = clock();
        dur = static_cast<double>(end - st);
        finalRes.encode0 = dur / CLOCKS_PER_SEC;
        cout << "the decoding processing has finished. The total time cost is:"
             << finalRes.encode0 << "s\n\n";

        norm.virError = cal_err(norm.virErrorData);
        printError(norm.virError);

        if (printAns) {
            cout << "the recovery result of pixes using FHE:\n";
            for (auto v : ans_fl) cout << v << " ";
            cout << endl;
        }
        return ans_fl;
    }

    /*----- CKKS 解密 -----*/
    vector<int> DecryPicCKKS(Decryptor& decryptor, CKKSEncoder& encoder,
                             Evaluator& evaluator, Norm& norm, Result& finalRes,
                             bool printAns = true) {
        Plaintext text1;
        vector<Ciphertext> a = pic_en;
        vector<double> temAns[10];
        vector<int> ans_fl;
        cout << "download from  the center server;\n"
             << "\n\n\nstart to decoder locally\n";
        double dur;
        clock_t st = clock(), end;

        for (size_t i = 0; i < a.size(); ++i) {
            decryptor.decrypt(a[i], text1);
            encoder.decode(text1, temAns[i]);
        }
        origin_pic.clear();
        for (int i = 0; i < batches; ++i)
            for (size_t j = 0; j < a.size(); ++j) {
                ans_fl.push_back(static_cast<int>(
                    (around(temAns[j][i]) + norm.modP) % norm.modP));
                norm.virErrorData.push_back(around(temAns[j][i]) - temAns[j][i]);
            }
        end = clock();
        dur = static_cast<double>(end - st);
        finalRes.encode0 = dur / CLOCKS_PER_SEC;
        cout << "the decoding processing has finished. The total time cost is:"
             << finalRes.encode0 << "s\n\n";

        norm.virError = cal_err(norm.virErrorData);
        printError(norm.virError);

        if (printAns) {
            cout << "the recovery result of pixes using FHE:\n";
            for (auto v : ans_fl) cout << v << " ";
            cout << endl;
        }
        return ans_fl;
    }

    void setBatches(int batches) { this->batches = batches; }
    int  getBatches() const { return batches; }
    void setPic(vector<int> a) { origin_pic = std::move(a); }

    double compare(const Picture& tem) const {
        if (tem.origin_pic.size() != origin_pic.size()) return 0;
        double flag = 0, total = origin_pic.size();
        for (size_t i = 0; i < origin_pic.size(); ++i)
            if (tem.origin_pic[i] == origin_pic[i]) ++flag;
        cout << "the correct rate of ans is " << (flag / total * 100) << "%\n";
        return flag / total * 100;
    }

    double compare(const Picture& tem, Norm& norm) const {
        if (tem.origin_pic.size() != origin_pic.size())
            throw runtime_error("sizes are different");
        for (size_t i = 0; i < origin_pic.size(); ++i)
            if (tem.origin_pic[i] != origin_pic[i]) {
                norm.realErrorData.push_back(fabs(tem.origin_pic[i] - origin_pic[i]));
                norm.realErrorIndex.push_back(static_cast<int>(i));
            }
        norm.realError = cal_err(norm.realErrorData);
        printError(norm.realError);
        return norm.realError.mean;
    }

private:
    vector<int> origin_pic;
    vector<ll> origin_sec, aerfa;
    vector<Ciphertext> pic_en;
    int siz[2]{};
    vector<double> origin_secCKKS;
    int batches{};
};

/*============================ SharePic ============================*/
class SharePic {
public:
    friend class Picture;
    explicit SharePic(Params& parms) : range_x(parms.rangeX), P(parms.ModP) {}

    void addNewPixByPlain(vector<ll> y, int x, bool BFV = true) {
        ll f = 0;
        int k = static_cast<int>(y.size());
        for (int i = 0; i < k; ++i)
            f += static_cast<ll>(pow(x, i)) * y[i];
        if (BFV) X.push_back(x);
        fx_div.push_back(static_cast<int>((f - f % P) / P));
        fx.push_back(static_cast<int>(f % P));
    }

    vector<ll> getX() { return X; }
    vector<int> getfx() { return fx; }
    void PrintFx() {
        for (auto v : fx) cout << v << " ";
        cout << endl << endl;
    }

    Ciphertext& addNewPixByCipher(vector<Ciphertext> y, Evaluator& evaluator,
                                  RelinKeys& rk, int index = 0) {
        static Ciphertext result;
        result = y[0];
        Ciphertext tem2;
        for (size_t i = 1; i < y.size(); ++i) {
            evaluator.exponentiate(x_en[index], static_cast<int>(i), rk, tem2);
            evaluator.multiply_inplace(tem2, y[i]);
            evaluator.add_inplace(result, tem2);
        }
        evaluator.relinearize_inplace(result, rk);   // 原代码 bug：对 tem2 重线性化无意义
        fx_en.push_back(result);
        return result;
    }

    Ciphertext generateCKKSShares(vector<Ciphertext> y, Evaluator& evaluator,
                                RelinKeys& rk, shared_ptr<seal::SEALContext>& context,
                                vector<Ciphertext>& ONES) {
        size_t k = y.size();
        Ciphertext ans = y[0], tem1;
        for (size_t i = 1; i < k; ++i) {
            vector<Ciphertext> tem;
            tem.push_back(y[i]);
            for (size_t j = 1; j <= i; ++j) tem.push_back(x_en[0]);
            tem1 = cal_mut(tem, evaluator, rk, context, ONES);
            add(evaluator, ans, tem1, context);
        }
        fx_en.push_back(ans);
        return ans;
    }

    Ciphertext generateBFVShares(vector<Ciphertext> y, Evaluator& evaluator,
                               RelinKeys& rk, shared_ptr<seal::SEALContext>& context,
                               Ciphertext& ONES) {
        size_t k = y.size();
        Ciphertext ans = y[0], tem1;
        for (size_t i = 1; i < k; ++i) {
            vector<Ciphertext> tem;
            tem.push_back(y[i]);
            for (size_t j = 1; j <= i; ++j) tem.push_back(x_en[0]);
            tem1 = cal_mutBFV(tem, evaluator, rk, ONES);
            evaluator.add_inplace(ans, tem1);
        }
        fx_en.push_back(ans);
        return ans;
    }

    void showShareCKKS(Decryptor& decryptor, CKKSEncoder& encoder, bool printAns = true) {
        Plaintext tem;
        vector<double> share_de;
        decryptor.decrypt(fx_en[0], tem);
        encoder.decode(tem, share_de);
        bool flag = true;
        for (int i = 0; i < X_len; ++i) {
            if (printAns) cout << around(share_de[i]) % P << " ";
            if (around(share_de[i]) % P != fx[i]) flag = false;
        }
        cout << (flag ? "the ans is correct" : "something is error!") << endl;
    }

    void showShareBFV(Decryptor& decryptor, BatchEncoder& encoder, bool printAns = true) {
        Plaintext tem;
        vector<int64_t> share_de;
        decryptor.decrypt(fx_en[0], tem);
        encoder.decode(tem, share_de);
        bool flag = true;
        for (int i = 0; i < X_len; ++i) {
            if (printAns) cout << around(share_de[i]) % P << " ";
            if (around(share_de[i]) % P != fx[i]) flag = false;
        }
        cout << (flag ? "the ans is correct" : "something is error!") << endl;
    }

    vector<int> fx, fx_div;
    vector<ll> X;
    int range_x{};
    vector<Ciphertext> x_en, fx_en;
    ll pix_de{}, pix_sr{};
    int rad{};
    int P{};
    int X_len{};
    Plaintext X_plain, fx_plain;
    vector<double> temVec;
};

/*============================ DecTools ============================*/
class DecTools {
public:
    vector<long long> m[64 * 64];
    vector<long long> K[64 * 64];
    vector<long long> invm[64 * 64];
    vector<long long> A[64 * 64];
    long long KT[64 * 64]{};
    long long invKT[64 * 64]{};
};