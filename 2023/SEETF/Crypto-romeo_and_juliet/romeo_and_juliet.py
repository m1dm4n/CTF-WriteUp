from Crypto.Util.number import getPrime, bytes_to_long
import os

flag = os.environ.get('FLAG', 'SEE{not_the_real_flagggggggggggggggggggggggggggggggggggggggggggggg}').encode()

# class Person:
#     def __init__(self):
#         p, q = getPrime(512), getPrime(512)
#         self.e = 65537
#         self.d = pow(self.e, -1, (p-1)*(q-1))
#         self.n = p * q
#     def hear(self, m): return pow(m, self.e, self.n)
#     def yell(self, c): return pow(c, self.d, self.n)

# Romeo, Juliet = Person(), Person()

class Person1:
    def __init__(self):
        p, q = 10940174123760583789378819748998728232970984353506846437227272370219801277400228385508659894753162210406733045403261621398992924492206424946231353211369571, 8139445421422883235934665831771471119036602448159890304110314841744982424244772828371266019651634227162090783985194489131076260921783639579036862814141299
        self.e = 3083
        self.d = pow(self.e, -1, (p-1)*(q-1))
        self.n = p * q

    def hear(self, m): return pow(m, self.e, self.n)
    def yell(self, c): return pow(c, self.d, self.n)
class Person2:
    def __init__(self):
        p, q = 11407668411722704284216283046589511278040074149751934000163774719663802805974774064222417866192534865616925616980259231093635787107251754372813280741584047, 9647193906011060227201478104756689753250538468120979542259535779509633441530777122174939663357812603694406058404449910886747976561449327479483519221056987
        self.e = 3083
        self.d = pow(self.e, -1, (p-1)*(q-1))
        self.n = p * q

    def hear(self, m): return pow(m, self.e, self.n)
    def yell(self, c): return pow(c, self.d, self.n)
Romeo, Juliet = Person1(), Person2()

noise = os.urandom(16)
print('Romeo hears the flag amidst some noise:', Romeo.hear(bytes_to_long(noise[:8] + flag + noise[8:])))

for _ in noise:
    print('Juliet hears:', Juliet.hear(Romeo.yell(int(input('Romeo yells: ')))))
    print('Romeo hears:', Romeo.hear(Juliet.yell(int(input('Juliet yells: ')))))

