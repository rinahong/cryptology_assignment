import csv
import re
import os

class letterCounter:
    """Task1: Count frequency of each letter repeated in the user-specified text file.

    How to compile and run in terminal:
        1) In the file directory, enter "python"
        2) from assign1 import *
        3) counter = letterCounter()
        4) counter.run()

    DATE: 2019-01-20
    DESIGNER/PROGRAMMER: Rina Hong

    Attributes:
        frequencyCounter     Frequency of each letter in the user-specified text file.
        read_file_name       User-specified text file to read.
        output_file_name     User-specified text file to write result.
    """

    frequencyCounter = {}
    read_file_name= ""
    output_file_name = ""
    total_numbers_of_letters = 0

    def run(self):
        """Runner function"""

        self.ask_user_input()
        self.read_file()
        self.output_result_to_csv()
        self.is_sum_of_probabilities_one()
        self.calculate_conditional_probability()
        self.frequencyCounter = {}

    def ask_user_input(self):
        """Prompt user to enter which file to read and enter csv file name"""
        option = ""
        while True:
            if option == '1' or option == '2' or option == '3':
                break
            option = raw_input("Please enter 1 or 2 or 3\n" +
            "1) Alice in Wonderland \n" + "2) MobyDick \n" +
            "3) None of the above, I will specify file name \n")

        if (option == '1' or option == '2'):
            self.read_file_name = {
                    '1': 'AliceInWonderland.txt',
                    '2': 'MobyDick.txt'
                }[option]
        else:
            while (not os.path.isfile(option)):
                option = raw_input("Enter an existing text file name ex) filename.txt: \n")
            self.read_file_name = option
        print "----------------------\n"

        self.output_file_name = raw_input("Please enter file name that you'd like to see the result ex) output.csv\n")

        while not re.search('.csv$', self.output_file_name):
            self.output_file_name = raw_input("Please enter file name ends with .csv: ")
        print "----------------------\n"

    def read_file(self):
        """Read text file and count the frequency of each letter"""
        with open(self.read_file_name, "r") as file:
            while True:
                letter = file.read(1)
                if not letter:
                  break
                if letter.lower().isalpha():
                    if letter.lower() in self.frequencyCounter.keys():
                        self.frequencyCounter[letter.lower()] += 1
                    else:
                        self.frequencyCounter[letter.lower()] = 1

        print "letters with frequencies: "
        print self.frequencyCounter, "\n"

    def output_result_to_csv(self):
        """Write frequency result to user-specified csv file"""

        with open(self.output_file_name, 'wb') as csvfile:
            frequencyWriter = csv.writer(csvfile)
            for key, value in self.frequencyCounter.items():
                frequencyWriter.writerow([key, str(value)])

    def is_sum_of_probabilities_one(self):
        """Calculate sum of probabilities and print out the result"""

        sum_of_probabilities = 0.0
        self.total_numbers_of_letters = float(sum(self.frequencyCounter.values()))
        print "Total letter count: %d \n" % self.total_numbers_of_letters
        for key, value in self.frequencyCounter.items():
            sum_of_probabilities += (value / self.total_numbers_of_letters)

        print "sum_of_probabilities: %f \n" % sum_of_probabilities

    def calculate_conditional_probability(self):
        """Calculate conditional probaility with user specified argument"""

        # most_freq_letters = ['e', 't', 'a', 'i', 'o', 'n']
        most_freq_letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
        'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y','z']
        probability_key = 1/26.0 #There are 26 alphabets
        probability_cipher = 1/26.0 #ci is an element in the set of C. C is 26 .
        for letter_m in most_freq_letters:
            probability_message = self.frequencyCounter[letter_m] / float(self.total_numbers_of_letters)
            conditional_probability = (probability_key * probability_message) / probability_cipher
            print "Conditional probability of %s is %2.8f" % (letter_m, conditional_probability)
