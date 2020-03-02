def gcd(a, n):
    for i in range(1, n):
        if ((i*a) % n == 1):
            return i
    
if __name__ == "__main__":
    phi = list(map(int, input('lista: ').split(' ')))
    modulo = int(input('Modulo: '))
    invPhi = []
    for number in phi:
        invPhi.append(gcd(number, modulo))
    for numberinv in invPhi:
        print(numberinv,end=' ')
        print()