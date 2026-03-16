#include "../include/tools.h"

void print_vec(vector<double>&vec,int num,int pres) {
  ios old_fmt(nullptr);
  old_fmt.copyfmt(cout);
  cout << fixed << setprecision(pres);

  size_t len = num * 2;
  if (vec.size() <= len) {
    vec.resize(len + 1);
  }
  cout << "[";
  for (size_t i = 0; i < (size_t)num; i++) {
    cout << vec[i] << ", ";
  }
  cout << "..., ";
  for (size_t i = vec.size() - num; i < vec.size(); i++) {
    cout << vec[i] << ", ";
  }
  cout << "]" << endl;
  cout.copyfmt(old_fmt);
}

void print_vec(vector<int>& vec, int num, int pres) {
  ios old_fmt(nullptr);
  old_fmt.copyfmt(cout);
  cout << fixed << setprecision(pres);

  size_t len = num * 2;
  if (vec.size() <= len) {
    vec.resize(len + 1);
  }
  cout << "[";
  for (size_t i = 0; i < (size_t)num; i++) {
    cout << vec[i] << ", ";
  }
  cout << "..., ";
  for (size_t i = vec.size() - num; i < vec.size(); i++) {
    cout << vec[i] << ", ";
  }
  cout << "]" << endl;
  cout.copyfmt(old_fmt);
}

void print_line(int tag) {
  for (int i = 0; i < tag; i++) {
    cout << endl;
  }
}

void PrintDeVec(Decryptor& decryptor, CKKSEncoder& encoder, Ciphertext& en) {
  Plaintext plain;
  decryptor.decrypt(en, plain);
  vector<double> temAns;
  encoder.decode(plain,temAns);
  print_vec(temAns, 5, 4);
  print_line();
}

void PrintDeVec(Decryptor& decryptor, CKKSEncoder& encoder, vector<Ciphertext>& en, int tag, int num) {
  Plaintext plain;
  vector<double> temAns;
  for (size_t i = 0; i < en.size(); i++) {
    decryptor.decrypt(en[i], plain);
    encoder.decode(plain, temAns);
    if (tag) {
      print_vec(temAns, num);
    }
    else {
      print_vec(temAns, 1);
    }
  }
  print_line();
}

Error cal_err(vector<double>& vec) {
  Error err;
  err.maxn = err.var = err.total = 0;
  for (size_t i = 0; i < vec.size(); i++) {
    err.total += vec[i];
    err.maxn = max(fabs((double)vec[i]), err.maxn);
  }
  err.mean = err.total / vec.size();
  for (size_t i = 0; i < vec.size(); i++) {
    err.var += pow(vec[i]-err.mean, 2);
  }
  err.var /= vec.size();
  err.dataScale = (int)vec.size();
  return err;
}

Error cal_err(vector<int> vec) {
  Error err;
  err.maxn = err.var = err.total = 0;
  for (size_t i = 0; i < vec.size(); i++) {
    err.total += vec[i];
    err.maxn = max((double)vec[i], err.maxn);
  }
  err.mean = err.total / vec.size();
  for (size_t i = 0; i < vec.size(); i++) {
    err.var += pow(vec[i] - err.mean, 2);
  }
  err.var /= vec.size();
  err.dataScale = (int)vec.size();
  return err;
}

void printError(Error& err) {
  cout << endl;
  ios old_fmt(nullptr);
  old_fmt.copyfmt(cout);
  cout << fixed << setprecision(3);
  cout << "the error detials[siz,totalsum, max, mean, var]: [" << err.dataScale << ", " << err.total << ", " << err.maxn << ", " << err.mean << ", " << err.var << "]" << endl;
  cout.copyfmt(old_fmt);
}

inline void outPutCiphertext(const std::vector<seal::Ciphertext>& text,
                             const std::string& filePre,
                             std::shared_ptr<seal::SEALContext> context)
{
    if (text.empty()) return;

    auto parms_id   = text[0].parms_id();
    auto ctx_data   = context->get_context_data(parms_id);
    auto coeff_cnt  = ctx_data->parms().coeff_modulus().size();
    auto poly_degree= ctx_data->parms().poly_modulus_degree();

    std::cout << "coeff_mod_count = " << coeff_cnt
              << "\npoly_modulus_degree = " << poly_degree << "\n";

    for (size_t i = 0; i < text.size(); ++i) {
        std::string fname = filePre + std::to_string(i) + ".txt";
        std::ofstream out(fname, std::ios::out | std::ios::binary);
        text[i].save(out);
        out.close();
    }
}

void outPutCiphertext(vector<Plaintext>& text, string filePre) {
  cout << filePre << endl;
  for (size_t i = 0; i < text.size(); i++) {
    cout << "the coeff_count is: " << text[0].coeff_count() <<
      "\n the poly_modulus_degree is: " << text[0].nonzero_coeff_count() << endl;
    string temName = filePre + to_string(i) + ".txt";
    fstream out(temName, ios::out | ios::binary);
    text[i].save(out);
    out.close();
  }
}