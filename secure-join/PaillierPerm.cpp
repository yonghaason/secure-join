


class PaillierPerm
{
    void apply()
    {
    //         if (isClient()) 
    // {
    //     Pl::RNG rand(mPrng.get());

    //     //generate Paillier key
    //     Pl::PrivateKey mSk;
    //     mSk.keyGen(secparam, rand);
    //     std::vector<u8> pkBytes(mSk.mPublicKey.sizeBytes());
    //     mSk.mPublicKey.toBytes(pkBytes);

    //     /*Encrypt the Feature vector */
    //     Pl::Plaintext msg;
    //     msg.setModulus(mSk.mPublicKey.mN);
    //     Pl::Ciphertext ct;
    //     std::vector<u8> encFeaturesBytes(mFeatures.size() * mSk.mPublicKey.ciphertextByteSize());
    //     oc::MatrixView<u8> view(encFeaturesBytes.begin(), encFeaturesBytes.end(), mSk.mPublicKey.ciphertextByteSize());

    //     for (int i = 0; i < mFeatures.size(); i++)
    //     {
            
    //         msg.setValue(Pl::Integer (mFeatures[i]));
    //         //generate the ciphertext
    //         mSk.mPublicKey.enc(msg, rand, ct);
    //         //Convert the ciphertext to bytes
    //         ct.toBytes(view[i]);
    //     }
        
    //     chl.asyncSend(std::move(pkBytes));
    //     chl.asyncSend(std::move(encFeaturesBytes));

    //     //Receive the encrypted mapped features from the server and decrypt
    //     std::vector<u8> buff;
    //     chl.recv(buff);
    //     oc::MatrixView<u8> buffView(buff.begin(), buff.end(), mSk.mPublicKey.ciphertextByteSize());
    //     for (u64 i = 0; i < mNumTrees; ++i)
    //     {
    //         for (u64 j = 0; j < mNumNodes; ++j)
    //         {
    //             ct.fromBytes(buffView[i*mNumNodes + j], mSk.mPublicKey);
    //             msg = mSk.dec(ct);
    //             mMappedFeatures(i,j) = (i64) msg; 
    //         }
    //     }
    // }
    // else
    // {
    //     std::vector<u8> buff;

    //     // Receive the public key.
    //     chl.recv(buff);
    //     Pl::PublicKey mPk;
    //     mPk.fromBytes(buff);
        
    //     // Receive the ciphertexts
    //     std::vector<Pl::Ciphertext> encFeatures;
    //     chl.recv(buff);
    //     oc::MatrixView<u8> buffView(buff.begin(), buff.end(), mPk.ciphertextByteSize());
    //     encFeatures.resize(buffView.rows());
    //     for (u64 i = 0; i < encFeatures.size(); ++i)
    //     {   
    //         encFeatures[i].fromBytes(buffView[i], mPk);
    //     }

    //     // Perform the homomorphic computation
    //     Pl::Plaintext msg;
    //     msg.setModulus(mPk.mN);
    //     Pl::Ciphertext ct;
    //     std::vector<u8> encMappedFeaturesBytes(mMappedFeatures.size() * mPk.ciphertextByteSize());
    //     oc::span<u8> view = encMappedFeaturesBytes;

    //     for (u64 i = 0; i < mNumTrees; ++i)
    //     {
    //         for (u64 j = 0; j < mNumNodes; ++j)
    //         {
    //             //generate random mMappedFeatures(i,j) and encrypt
    //             Pl::RNG rand1(mPrng.get());
    //             msg.randomize(rand1); 
    //             Pl::RNG rand2(mPrng.get());
    //             mPk.enc(msg, rand2, ct);
    //             mMappedFeatures(i,j) = (i64) msg;

    //             // Homomorphically add to EncFeatures[mMapping(i,j)];
    //             ct.add(ct, encFeatures[mMapping(i,j)]);
                
    //             //Convert the ciphertext to bytes
    //             auto sub = view.subspan(0, mPk.ciphertextByteSize());
    //             ct.toBytes(sub);
    //             view = view.subspan(mPk.ciphertextByteSize());
    //         }
    //     }
    //     if(view.size() !=0)
    //     {
    //         throw RTE_LOC;
    //     }

    //     chl.asyncSendCopy(encMappedFeaturesBytes);
    // }
    // //Convert from additive to xor sharing using GMW
    // auto subCir = mLib.int_int_subtract(64, 64, 64);
    // u64 pIdx = isClient() ? 1 : 0;
    // auto features = oc::MatrixView<i64>(mMappedFeatures);
    // features.reshape(features.size(), 1);
    // mGmw.init(features.size(), *subCir, 1, pIdx, mPrng.get());

    // if(isClient())
    // {
    //     mGmw.setInput(0, features);
    //     mGmw.setZeroInput(1);
    // }
    // else
    // {
    //     mGmw.setZeroInput(0);
    //     mGmw.setInput(1, features);  
    // }   
    // mGmw.run(chl);
        
    // Matrix<u8> out;
    // out.resize(features.size(), sizeof(i64));
    // mGmw.getOutput(0, out); 
    // oc::MatrixView<u8> v((u8*)mMappedFeatures.data(), mMappedFeatures.size(), sizeof(i64));
    // for (int i = 0; i < v.size(); ++i)
    //     {   
    //         v(i) = out(i);
    //     }
    }
};

