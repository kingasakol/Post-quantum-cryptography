import numpy as np

#todo

def seed_expander(category, n0):
    return np.array(((0, 43),
                               (2843, 44),
                               (4392, 45),
                               (5193, 46),
                               (5672, 47)), dtype=np.int64)



if __name__ == "__main__":
    print(seed_expander(None, None))