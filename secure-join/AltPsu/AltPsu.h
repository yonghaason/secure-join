#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/BitVector.h"
#include "secure-join/GMW/Gmw.h"
#include "band_okvs.h"
#include "uint.h"

namespace secJoin
{
    using Proto = coproto::task<>;
    using Socket = coproto::Socket;

    class AltModPsuSender : public oc::TimerAdapter
    {        
        oc::Timer timer;

    public:

        Proto run(span<block> Y, PRNG &prng, Socket &chl);
        Proto run_debug(span<block> Y, PRNG &prng, Socket &chl, Socket &socket_gmw);
        Proto run_correctness(span<block> Y, PRNG &prng, Socket &chl, Socket &socket_gmw);
        Proto run_gmw_test(span<block> Y, PRNG &prng, Socket &chl);
        Proto run_unbalance(span<block> Y, span<block> X, PRNG &prng, Socket &chl, Socket &socket_gmw);

    };

    class AltModPsuReceiver :public oc::TimerAdapter
    {
        oc::Timer timer;
        oc::Timer timer2;
        oc::Timer timer3;
    public:

        Proto run(span<block> X, std::vector<block>& D, PRNG &prng, Socket &chl);
        Proto run_debug(span<block> X, PRNG &prng, Socket &chl, Socket &socket_gmw);
        Proto run_correctness(span<block> X, PRNG &prng, Socket &chl, Socket &socket_gmw);
        Proto run_gmw_test(span<block> X, PRNG &prng, Socket &chl);
        Proto run_unbalance(span<block> X, span<block> Y, PRNG &prng, Socket &chl, Socket &socket_gmw);

    };

}
