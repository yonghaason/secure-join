#pragma once

#include "secure-join/Defines.h"
#include "secure-join/Prf/DLpnPrf.h"
#include "secure-join/Perm/Permutation.h"

namespace secJoin
{

    class DLpnPerm
    {
    public:
        DLpnPrfReceiver mRecver;
        DLpnPrfSender mSender;
        oc::Matrix<u8> mA, mDelta, mB;

        void setupDlpnSender(oc::block &key, std::vector<oc::block> &rk);

        void setupDlpnReceiver(std::vector<std::array<oc::block, 2>> &sk);

        macoro::task<> setupDlpnSender(OleGenerator &ole);
        
        macoro::task<> setupDlpnReceiver(OleGenerator &ole);

        // DLpn Receiver calls this setup
        macoro::task<> setup(
            const Perm &pi,
            u64 bytesPerRow,
            oc::PRNG &prng,
            coproto::Socket &chl,
            OleGenerator &ole,
            bool invPerm);

        // DLpn Sender calls this setup
        macoro::task<> setup(
            oc::PRNG &prng,
            coproto::Socket &chl,
            OleGenerator &ole,
            u64 totElements,
            u64 bytesPerRow);

        // DLpn Receiver calls this apply
        macoro::task<> apply(
            const Perm &pi,
            oc::MatrixView<u8> sout,
            u64 bytesPerRow,
            coproto::Socket &chl,
            bool invPerm);

        // DLpn Sender calls this apply
        macoro::task<> apply(
            oc::MatrixView<const u8> input,
            oc::MatrixView<u8> sout,
            coproto::Socket &chl);

        template <typename T>
        macoro::task<> apply(
            const Perm &pi,
            u64 bytesPerRow,
            oc::PRNG &prng,
            coproto::Socket &chl,
            OleGenerator &ole,
            oc::MatrixView<T> sout,
            bool invPerm);

        // If DLPN receiver only wants to call apply
        // this will internally call setup for it
        template <>
        macoro::task<> apply<u8>(
            const Perm &pi,
            u64 bytesPerRow,
            oc::PRNG &prng,
            coproto::Socket &chl,
            OleGenerator &ole,
            oc::MatrixView<u8> sout,
            bool invPerm);


        // Generic version of below method
        template <typename T>
        macoro::task<> apply(
            const Perm &pi,
            oc::PRNG &prng,
            coproto::Socket &chl,
            OleGenerator &ole,
            oc::MatrixView<const T> in,
            oc::MatrixView<T> sout,
            bool invPerm);

        // If DLPN receiver only wants to call apply
        // when it also has inputs
        // this will internally call setup for it
        template <>
        macoro::task<> apply<u8>(
            const Perm &pi,
            oc::PRNG &prng,
            coproto::Socket &chl,
            OleGenerator &ole,
            oc::MatrixView<const u8> in,
            oc::MatrixView<u8> sout,
            bool invPerm);

        // Generic version of below method
        template <typename T>
        macoro::task<> apply(
            oc::PRNG &prng,
            coproto::Socket &chl,
            OleGenerator &ole,
            oc::MatrixView<const T> in,
            oc::MatrixView<T> sout);

        // If DLPN sender only wants to call apply
        // this will internally call setup for it
        template <>
        macoro::task<> apply<u8>(
            oc::PRNG &prng,
            coproto::Socket &chl,
            OleGenerator &ole,
            oc::MatrixView<const u8> input,
            oc::MatrixView<u8> sout);
    };

    template <typename T>
    macoro::task<> DLpnPerm::apply(
        const Perm &pi,
        u64 bytesPerRow,
        oc::PRNG &prng,
        coproto::Socket &chl,
        OleGenerator &ole,
        oc::MatrixView<T> sout,
        bool invPerm)
    {
        oc::MatrixView<u8> oo((u8 *)sout.data(), sout.rows(), sout.cols() * sizeof(T));
        return apply<u8>(pi, bytesPerRow, prng, chl, ole, sout, invPerm);
    }


        // Generic version of below method
        template <typename T>
        macoro::task<> DLpnPerm::apply(
            const Perm &pi,
            oc::PRNG &prng,
            coproto::Socket &chl,
            OleGenerator &ole,
            oc::MatrixView<const T> in,
            oc::MatrixView<T> sout,
            bool invPerm)
        {
            oc::MatrixView<const u8> xx((u8 *)in.data(), in.rows(), in.cols() * sizeof(T));
            oc::MatrixView<u8> oo((u8 *)sout.data(), sout.rows(), sout.cols() * sizeof(T));
            return apply<u8>(pi, prng, chl, ole, xx, oo, invPerm);
        }


        // Generic version of below method
        template <typename T>
        macoro::task<> DLpnPerm::apply(
            oc::PRNG &prng,
            coproto::Socket &chl,
            OleGenerator &ole,
            oc::MatrixView<const T> in,
            oc::MatrixView<T> sout)
        {
            oc::MatrixView<const u8> xx((u8 *)in.data(), in.rows(), in.cols() * sizeof(T));
            oc::MatrixView<u8> oo((u8 *)sout.data(), sout.rows(), sout.cols() * sizeof(T));
            return apply<u8>(prng, chl, ole, xx, oo);
        }

}