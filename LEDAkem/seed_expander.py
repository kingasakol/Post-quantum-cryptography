import numpy as np

def seed_expander(category, n0):
    if category == 1 and n0 == 2:
        return np.array(((0, 43),
                                   (2843, 44),
                                   (4392, 45),
                                   (5193, 46),
                                   (5672, 47)), dtype=np.int64)

    if (category == 2 or category == 3) and n0 == 2:
        return np.array(((0, 61),
                               (3957, 62),
                               (6698, 63),
                               (8128, 64),
                               (8978, 65),
                               (9578, 66),
                               (9981, 67),
                               (10286, 68),
                               (10533, 69)), dtype=np.int64)

    if(category == 4 or category == 5) and n0 == 2:
        return np.array(((0, 74),
                               (5742, 75),
                               (10032, 76),
                               (12263, 77),
                               (13621, 78),
                               (14538, 79),
                               (15211, 80),
                               (15706, 81),
                               (16091, 82),
                               (16391, 83),
                               (16640, 84)), dtype=np.int64)

    if category == 1 and n0 == 3:
        return np.array(((0, 49),
                               (2509, 50),
                               (3124, 51),
                               (3478, 52),
                               (3695, 53),
                               (3878, 54)), dtype=np.int64)

    if(category == 2 or category == 3) and n0 == 3:
        return np.array(((0, 71),
                               (4255, 72),
                               (5492, 73),
                               (6203, 74),
                               (6666, 75),
                               (7021, 76),
                               (7271, 77),
                               (7466, 78),
                               (7617, 79)), dtype=np.int64)

    if (category == 4 or category == 5) and n0 == 3:
        return np.array(((0, 88),
                                (6551, 89),
                                (8560, 90),
                                (9789, 91),
                                (10536, 92),
                                (11123, 93),
                                (11519, 94),
                                (11837, 95),
                                (12091, 96),
                                (12319, 97)), dtype=np.int64)

    if category == 1 and n0 == 4:
        return np.array(((0, 53),
                               (2021, 54),
                               (2611, 55),
                               (2957, 56),
                               (3181, 57),
                               (3345, 58),
                               (3447, 59)), dtype=np.int64)

    if (category == 2 or category == 3) and n0 == 4:
        return np.array(((0, 71),
                               (3244, 72),
                               (4359, 73),
                               (5006, 74),
                               (5408, 75),
                               (5712, 76),
                               (5915, 77),
                               (6094, 78),
                               (6230, 79)), dtype=np.int64)

    if (category == 4 or category == 5) and n0 == 4:
        return np.array(((0, 88),
                               (4788, 89),
                               (6581, 90),
                               (7620, 91),
                               (8300, 92),
                               (8782, 93),
                               (9121, 94),
                               (9386, 95),
                               (9593, 96),
                               (9780, 97)), dtype=np.int64)


if __name__ == "__main__":
    print(seed_expander(None, None))