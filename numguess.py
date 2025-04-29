import random

# Ask for upper bound
top_of_range = input("Type a number: ")

# Check input is a digit
if top_of_range.isdigit():
    top_of_range = int(top_of_range)

    if top_of_range <= 0:
        print("Please type a number larger than zero.")
        quit()
else:
    print("Please type a number next time.")
    quit()

# Generate random number between 1 and top_of_range
random_number = random.randint(1, top_of_range)
guesses = 0

# Game loop
while True:
    user_guess = input("Make a guess: ")
    guesses += 1

    if user_guess.isdigit():
        user_guess = int(user_guess)
    else:
        print("Please type a number next time.")
        continue

    # Compare the guess to the actual number
    if user_guess == random_number:
        print("You got it!")
        break
    elif user_guess > random_number:
        print("You were above the number.")
    else:
        print("You were below the number.")

print("You got it in", guesses, "guesses.")

