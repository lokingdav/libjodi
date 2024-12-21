import asyncio, time, random, traceback
from pylibcpex import Oprf, Ciphering, Utils, KeyRotation

def func1(callDetails, sk, pk):
    (x1, r1) = Oprf.blind(callDetails)
    (x2, r2) = Oprf.blind(callDetails)
    
    (fx1, vk1) = Oprf.evaluate(sk, pk, x1)
    (fx2, vk2) = Oprf.evaluate(sk, pk, x2)
    
    digest1 = Oprf.unblind(fx1, vk1, r1)
    digest2 = Oprf.unblind(fx2, vk2, r2)
    
    assert(digest1 == digest2)
    print('========== Func1 checks passed! ==========')
    
def func2(callDetails, sk, pk):
    print('\nCall details:', callDetails)
    print('Secret key:', Utils.to_base64(sk))
    print('Public key:', Utils.to_base64(pk))
    # Check for correctness first
    (x1, r1) = Oprf.blind(callDetails)
    (x2, r2) = Oprf.blind(callDetails)
    assert(x1 != x2) # blindings must differ
    assert(r1 != r2) # random scalars must differ
    (fx1, vk1) = Oprf.evaluate(sk, pk, x1)
    (fx2, vk2) = Oprf.evaluate(sk, pk, x2)
    assert(fx1 != fx2) # intermediate evaluations must differ
    assert(vk1 == vk2 == pk) # verification params must be public key of PRF key
    digest1 = Oprf.unblind(fx1, vk1, r1)
    digest2 = Oprf.unblind(fx2, vk2, r2)
    assert(digest1 == digest2) # Must final unblinded results must match
    print('========== Func2 checks passed! ==========')

async def main():
    callDetails = '12345678900987654321' + str(int(time.time()))
    
    (sk, pk) = Oprf.keygen()
    try:
        func1(callDetails, sk, pk)
    except AssertionError:
        traceback.print_exc()
        print('func1 failed')
    
    try:
        func2(callDetails, sk, pk)
    except AssertionError:
        traceback.print_exc()
        print('func2 failed')
    
    

if __name__ == '__main__':
    asyncio.run(main())