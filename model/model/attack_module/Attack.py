class Attack:

    def __init__(self, id="common_hack", label="", frequency=None):
        self.id = id
        self.label = label
        self.properties = {}
        self.frequency = frequency

        if frequency is None:
            if label == "common_hack":
                self.frequency = 52 / 365.
            elif label == "targeted_hack":
                self.frequency = 1 / 365.
            elif label == "kiddie":
                self.frequency = 3 * 52 / 365.
            elif label == "social_eng":
                self.frequency = 3 * 52 / 365.
        else:
            self.frequency = frequency


if __name__ == '__main__':
    attack = Attack(id="common_hack", label="DDOS")
