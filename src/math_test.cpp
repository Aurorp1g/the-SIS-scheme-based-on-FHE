#include "../include/math_test.h"

int limit[] = { 2, 4, 8, 16, 32, 64, 128 };

int getLevel(Ciphertext& tem, shared_ptr<seal::SEALContext>& context, int tag) {
  int level = context->get_context_data(tem.parms_id())->chain_index();
  if (tag && !level) {
    cout << "the scale is not support multiply again";
    throw "the scale is not support multiply again";
  }
  else {
    return level;
  }
}

void modifyCipScale(Evaluator& evaluator, Ciphertext& tem, parms_id_type param_id, double scale) {
  evaluator.mod_switch_to_inplace(tem, param_id);
  tem.scale() = scale;
}

int reSize(int tem) {
  int i;
  for (i = 0; i < 7; i++) {
    if (tem <= limit[i])
      break;
  }
  return limit[i];
}

void multiply(Ciphertext& tem1, Ciphertext tem2, Evaluator& evaluator, RelinKeys& relin_key) {
  ios old_fmt(nullptr);
  old_fmt.copyfmt(cout);
  cout << fixed << setprecision(10);
  evaluator.multiply_inplace(tem1, tem2);
  evaluator.relinearize_inplace(tem1, relin_key);
  evaluator.rescale_to_next_inplace(tem1);
  cout.copyfmt(old_fmt);
}

void multiply1(Ciphertext& tem1, Ciphertext tem2, Evaluator& evaluator, RelinKeys& relin_key) {
  evaluator.multiply_inplace(tem1, tem2);
  evaluator.relinearize_inplace(tem1, relin_key);
}

void fitSize2(vector<Ciphertext>& vec, shared_ptr<seal::SEALContext>& context, vector<Ciphertext>& ONES, Evaluator& evaluator, RelinKeys& relin_keys) {
  if (vec.size() == 1)
    return;
  int minn = 10, tem, minn_id = 0;
  parms_id_type minn_p;
  for (int i = 0; i < vec.size(); i++) {
    tem = context->get_context_data(vec[i].parms_id())->chain_index();
    if (minn > tem) {
      minn = tem;
      minn_p = vec[i].parms_id();
      minn_id = i;
    }
  }
  int  siz = vec.size();
  int real_siz = reSize(siz);

  for (int i = 0; i < siz; i++) {
    tem = context->get_context_data(vec[i].parms_id())->chain_index();
    if (tem > minn) {
      modifyCipScale(evaluator, vec[i], minn_p, vec[minn_id].scale());
    }
  }
  for (int i = siz; i < real_siz; i++) {
    vec.push_back(ONES[minn]);
  }
}

void fitSize(vector<Ciphertext>& vec, shared_ptr<seal::SEALContext>& context, vector<Ciphertext>& ONES, Evaluator& evaluator, RelinKeys& relin_keys) {
  if (vec.size() == 1)
    return;
  int minn = 10, tem;
  for (int i = 0; i < vec.size(); i++) {
    tem = context->get_context_data(vec[i].parms_id())->chain_index();
    minn = minn < tem ? minn : tem;
  }
  int  siz = vec.size();
  int real_siz = reSize(siz);

  for (int i = 0; i < siz; i++) {
    tem = context->get_context_data(vec[i].parms_id())->chain_index();
    while (tem > minn) {
      multiply(vec[i], ONES[tem], evaluator, relin_keys);
      tem--;
    }
  }
  for (int i = siz; i < real_siz; i++) {
    vec.push_back(ONES[minn]);
  }
}

void fitSize4(vector<Ciphertext>& vec, shared_ptr<seal::SEALContext>& context, vector<Ciphertext>& ONES, Evaluator& evaluator, RelinKeys& relin_keys) {
  if (vec.size() == 1)
    return;
  int minn = 10, tem;
  for (int i = 0; i < vec.size(); i++) {
    tem = context->get_context_data(vec[i].parms_id())->chain_index();
    minn = minn < tem ? minn : tem;
  }
  int  siz = vec.size();
  int real_siz = reSize(siz);

  for (int i = 0; i < siz; i++) {
    tem = context->get_context_data(vec[i].parms_id())->chain_index();
    while (tem > minn) {
      multiply(vec[i], ONES[tem], evaluator, relin_keys);
      tem--;
    }
  }
  for (int i = siz; i < real_siz; i++) {
    vec.push_back(ONES[minn]);
  }
}

Ciphertext cal_mut(vector<Ciphertext> vec, Evaluator& evaluator, RelinKeys& relin_keys, shared_ptr<seal::SEALContext>& context, vector<Ciphertext>& ONES) {
  vector<Ciphertext> pre_ans;
  fitSize(vec, context, ONES, evaluator, relin_keys);
  while (vec.size() > 1) {
    for (size_t i = 0; i < vec.size(); i += 2) {
      Ciphertext tem = vec[i];
      multiply(tem, vec[i + 1], evaluator, relin_keys);
      pre_ans.push_back(tem);
    }
    vec = pre_ans;
    pre_ans.clear();
  }
  return vec[0];
}

Ciphertext cal_mutBFV(vector<Ciphertext> vec, Evaluator& evaluator, RelinKeys& relin_keys, Ciphertext& ONES) {
  vector<Ciphertext> pre_ans;
  while (vec.size() > 1) {
    for (size_t i = 0; i < vec.size(); i += 2) {
      Ciphertext tem = vec[i];
      multiply1(tem, vec[i + 1], evaluator, relin_keys);
      pre_ans.push_back(tem);
    }
    vec = pre_ans;
    pre_ans.clear();
  }
  return vec[0];
}

Ciphertext cal_mut1(vector<Ciphertext> vec, Evaluator& evaluator, RelinKeys& relin_keys, shared_ptr<seal::SEALContext>& context, vector<Ciphertext>& ONES, Decryptor& decryptor, CKKSEncoder& encoder) {
  vector<Ciphertext> pre_ans;
  fitSize4(vec, context, ONES, evaluator, relin_keys);
  while (vec.size() > 1) {
    for (size_t i = 0; i < vec.size(); i += 2) {
      Ciphertext tem = vec[i];
      multiply(tem, vec[i + 1], evaluator, relin_keys);
      pre_ans.push_back(tem);
    }
    vec = pre_ans;
    pre_ans.clear();
  }
  return vec[0];
}

void add(Evaluator& evaluator, Ciphertext& destinction, Ciphertext& tem2, shared_ptr<seal::SEALContext>& context) {
  int level1 = getLevel(destinction, context);
  int level2 = getLevel(tem2, context);
  if (level1 < level2) {
    modifyCipScale(evaluator, tem2, destinction.parms_id(), destinction.scale());
  }
  else if(level1>level2) {
    modifyCipScale(evaluator, destinction, tem2.parms_id(), tem2.scale());
  }
  evaluator.add_inplace(destinction, tem2);
}

void sub(Evaluator& evaluator, Ciphertext& destinction, Ciphertext& tem2, shared_ptr<seal::SEALContext>& context) {
  int level1 = getLevel(destinction, context);
  int level2 = getLevel(tem2, context);
  if (level1 < level2) {
    modifyCipScale(evaluator, tem2, destinction.parms_id(), destinction.scale());
  }
  else if (level1 > level2) {
    modifyCipScale(evaluator, destinction, tem2.parms_id(), tem2.scale());
  }
  evaluator.sub_inplace(destinction, tem2);
}

void add(Evaluator& evaluator, Ciphertext& tem1, Ciphertext& tem2, Ciphertext& destinction, shared_ptr<seal::SEALContext>& context) {
  int level1 = getLevel(tem1, context);
  int level2 = getLevel(tem2, context);
  if (level1 < level2) {
    modifyCipScale(evaluator, tem2, tem1.parms_id(), tem1.scale());
  }
  else if (level1 > level2) {
    modifyCipScale(evaluator, tem1, tem2.parms_id(), tem2.scale());
  }
  evaluator.add(tem1, tem2,destinction);
}

void sub(Evaluator& evaluator, Ciphertext& tem1, Ciphertext& tem2, Ciphertext& destinction, shared_ptr<seal::SEALContext>& context) {
  int level1 = getLevel(tem1, context);
  int level2 = getLevel(tem2, context);
  if (level1 < level2) {
    modifyCipScale(evaluator, tem2, tem1.parms_id(), tem1.scale());
  }
  else if (level1 > level2) {
    modifyCipScale(evaluator, tem1, tem2.parms_id(), tem2.scale());
  }
  evaluator.sub(tem1, tem2, destinction);
}

int around(double x) {
  return (x > 0 ? floor(x + 0.5) : ceil(x - 0.5));
}