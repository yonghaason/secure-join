#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/BitVector.h"
#include "secure-join/GMW/Gmw.h"
#include "RB_OKVS/band_okvs.h"
#include "RB_OKVS/uint.h"

namespace secJoin
{
    using Proto = coproto::task<>;
    using Socket = coproto::Socket;

    class AltModPsuSender : public oc::TimerAdapter
    {        

    public:

        Proto run(span<block> Y, PRNG &prng, Socket &chl);

    };

    class AltModPsuReceiver :public oc::TimerAdapter
    {

    public:

        Proto run(span<block> X, std::vector<block>& D, PRNG &prng, Socket &chl);

    };

}
