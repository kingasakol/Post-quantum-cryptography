import numpy as np


def trim_unnecessary_zeros(a):
    return np.trim_zeros(a, trim='b')

def padding(a, n):
    return np.pad(a, (0, n - len(a)), 'constant', constant_values=(0))


def transform_to_the_same_dim(a, b):
    if len(a) > len(b):
       return a, padding(b, len(a))

    elif len(a) < len(b):
        return padding(a, len(b)), b

    else:
        return a, b
