from sage.all import *
from sage.modules.free_module_integer import IntegerLattice

"""
    DISCLAIMER:
    This code is not mine.
    Idea is taken from "https://github.com/rkm0959/Inequality_Solving_with_CVP/blob/main/solver.sage"
    Re-coded for understanding purpose only.
"""

"""
    /function/ BabaiCVP():

    "" Purpose:
        Find the closest vector to a target vector.
        Original algorithm created by Babai.

    "" Args:
        basis:  The matrix composed of basis vectors.
        target: The target vector.
"""
def BabaiCVP(basis, target):
    reduced_basis   = IntegerLattice(basis, lll_reduce=True).reduced_basis
    reduced = reduced_basis.gram_schmidt()[0]
    diff    = target

    for i in reversed(range(reduced_basis.nrows())):
        diff -= reduced_basis[i] * ((diff * reduced[i]) / (reduced[i] * reduced[i])).round()

    return target - diff


"""
    /function/ CVP_rkm0959():

    "" Purpose:
        Approximate a vector in the range [l, r].
        Seems to have been optimised with scaling and stuff (?)

    "" Author:
        rkm0959

    "" Args:
        basis:   The matrix composed of basis vectors.
        l:       The lower bound target vector.
        r:       The upper bound target vector.
        weight:  For scaling up vectors.
        verbose: To display more information.
"""


def CVP_rkm0959(mat, lbs, rbs, weight=None, verbose=False, sanity_check=True):
    basis = mat[:, :]
    l = lbs[:]
    r = rbs[:]
    nrows = basis.nrows()
    ncols = basis.ncols()


    # Sanity checks
    if sanity_check:
        if len(l) != ncols:
            raise ValueError(f'[ ! ] The dimension of the lower-bound vector != dimension of basis vectors: {len(l)} != {ncols}')
        if len(r) != ncols:
            raise ValueError(f'[ ! ] The dimension of the upper-bound vector != dimension of basis vectors: {len(l)} != {ncols}')
        for d in range(ncols):
            if l[d] > r[d]:
                raise ValueError(f'[ ! ] Lower-bound vector should have all the elements smaller than upper-bound vectors!\nl={l}\nr={r}')


    # Estimate the number of possible solutions (verbose=True).
    # However, only calculable if the basis matrix is square one.
    if verbose:
        if nrows == ncols:
            DET     = abs(basis.det())
            num_sol = 1
            for i in range(ncols):
                num_sol *= (r[i] - l[i])

            if DET == 0:
                print(f"[ i ] Could not estimate the number of solutions, since the determinant of basis matrix is 0.")
            else:
                num_sol //= DET
                # + 1 added in for the sake of not making it zero...
                print(f"[ i ] Expected number of solutions: {num_sol + 1}")
        else:
            print(f"[ i ] Could not estimate the number of solutions, since the size of basis matrix is {nrows}x{ncols}, not square one.")


    # Set weight... Why?
    maxElement = max([max([abs(basis[i, j]) for i in range(nrows)]) for j in range(ncols)])
    if not weight:
        weight = ncols * maxElement


    # Scaling the vectors (to form some sort of high-dimensional sphere?)
    maxDiff        = max([r[d] - l[d] for d in range(ncols)])
    appliedWeights = []


    # Scaling some of the dimensions of the bound vectors & the matrix.
    for d in range(ncols):
        scaleFactor = weight if l[d] == r[d] else maxDiff // (r[d] - l[d])
        appliedWeights.append(scaleFactor)
        for i in range(nrows):
            basis[i, d] *= scaleFactor
        l[d] *= scaleFactor
        r[d] *= scaleFactor


    # Find closest vector to middle vector of (l, r)
    # = close to (l, r)
    m      = vector([(l[d] + r[d]) // 2 for d in range(ncols)])
    result = BabaiCVP(basis, m)


    # Sanity checking after this...
    if sanity_check:
        for d in range(ncols):
            if not (l[d] <= result[d] <= r[d]):
                if verbose:
                    print('[ i ] The result target is not in between lower-bound & upper-bound vector!')
                result = None
                break


    # Recover input.
    if result is not None:
        for d in range(ncols):
            result[d] /= appliedWeights[d]
    return result

"""
    /function/ CVP():

    "" Purpose:
        Approximate a lattice vector in [l, r].

    "" Args:
        basis:              The matrix composed of basis vectors.
        l:                  The lower bound target vector.
        r:                  The upper bound target vector.

        weight=None:        For scaling up vectors.

        verbose=False:      Print more outputs.
        
"""


def CVP(basis, l, r, weight=None, verbose=False, sanity_check=True):
    if verbose:
        print(f'================= DEBUG CVP =======================')

        print(f'[ i ] Target range vectors: {l} -> {r}')
        print(f'[ i ] Basis:')
        print(basis)
        print()

    result = CVP_rkm0959(basis, l, r, weight, verbose, sanity_check)

    if verbose:
        def _dist(v, w):
            return float(sqrt(sum([(a-b)**2 for a, b in zip(v, w)])))

        print(f'[ i ] Result vector: {result if result else "-NaV-"}')
        print(f'[ i ] Lattice coordinate: {basis.transpose().inverse() * result}')
        print(f'[ i ] Distance:')
        print(f'      [ + ] Result -> Lower: {_dist(l, result)}')
        print(f'      [ + ] Result -> Upper: {_dist(r, result)}')
        print()

    return result


if __name__ == '__main__':
    def _add(v: list, w: list) -> list:
        return [a+b for a, b in zip(v, w)]

    def _rand(no_vecs, no_dims, lower=1, upper=100):
        return [[Integer(randrange(lower, upper)) for __ in range(no_dims)] for _ in range(no_vecs)]


    n       = 10
    basis   = matrix(_rand(n+1, n))
    lower   = vector(_rand(1, n, upper=10000)[0])
    upper   = _add(lower, vector(_rand(1, n, upper=1000)[0]))

    basis = matrix([
        [52,86, 1,58,30,64,62,94,51,88],
        [ 3,17,86,33,68,33,86,95,41, 3],
        [49,11,21,51,29,55,15,24,37,94],
        [33,69,42, 3,25,90,52,34,40,32],
        [86,95,21,40,68,82,18, 9,73,13],
        [60,16,58,49,92,24,44,72,48,23],
        [ 9,42,73,17,46,65,75,10,92,92],
        [22,55,13, 7,81,35,97,52,67,79],
        [46,55,93,65,60,44,72,91,22,49],
        [ 7,91, 4,98,14,55,49,87,73,75],
        [34,35,15,77,24,92, 8,16,40, 1],
    ])

    lower = [4356, 2985, 4780, 4505, 2136, 6112, 1943, 1603, 5357, 6008]
    upper = [4544, 3760, 5146, 5345, 3006, 7077, 2480, 1661, 5583, 6584]

    CVP(basis, lower, upper, verbose=True)
 