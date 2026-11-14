# Trusted sources for Password Policies

# Minimum Password requirements by cisa.gov:

#    Long: At least 16 characters long (more is better)
#    Random: A mix of upper/lowercase letters, numbers and symbols or a passphrase of 5–7 unrelated words
#    Unique: Used for only one account

#https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/require-strong-passwords


# Password with unique characters by OWASP.org:

#   Allow usage of all characters including unicode and whitespace. 
#   There should be no password composition rules limiting the type of characters permitted. 

#https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#password-recovery


# Additional Information:
# https://pages.nist.gov/800-63-4/sp800-63b/passwords/


# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---

                #########################################################
                #            Password Analytics Tool (V2)               #
                #########################################################



# Text Coloring
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"
BLINK = "\033[7m"


session = 0



# These are the common special charaters that are normally allowed.
special_char = ["-", "_", "!", ".", "@", "#", "$", "?", "&", " "]
# Note: organizations often restrict specific special characters such as an apostrophe ('), quotation marks ("), etc. to prevent code injections
numeric_char = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]

def password_Analytics(password,filepath):
    strength_score = 0
    

    #########################################################
    #     This Section Handels The Password Length          #
    #########################################################
    password_length = len(password)


    if (password_length >= 6) and (password_length < 8): 
        strength_score += 1 #Its reccomended that ppasswords should be at LEAST 8 characters long
    elif (password_length >= 8) and (password_length <=16):
        strength_score += 10 #Gold Standard for password length. 
    elif password_length >= 16:
        # This is for Elite Password length. An Extra point is rewarded for any extra character passed 13.
        strength_score = strength_score + 11 + (password_length - 16)  
    else: # If the password length is less than 6 characters it rewards zero points.
        strength_score = 0 

    
    #########################################################
    #             This Section Handels rewarding            #
    #########################################################

    password_char = password
    password_char = list(password_char)

    containsUppercase = False
    containsLowercase = False
    containsSpecial = False
    containsNumber = False
    is_Identical = True
    is_leaked = False
    missingAttributes = 0  
    first_Char = password_char[0]

    for character in password_char:
        if character in special_char:
            # print("SPECIAL CHARACTER FOUND!")
            containsSpecial = True
            strength_score += 2#Adds strength score for every special Character
        if character.isupper():
            # print("Password contains an Uppercase Character")
            containsUppercase = True
        if character.islower():
            # print("Password contains a LowerCase Character")
            containsLowercase = True
        if character in numeric_char:
            # print("NUMERIC CHARACTER FOUND!")
            containsNumber = True
            strength_score += 2


    if containsUppercase and containsLowercase:
        # print("Password contains an upper and lower case characters.")
        strength_score += 3

    #########################################################
    #     This Section Handels deductions                   #
    #########################################################
    

    if containsSpecial == False:
        strength_score -= 5
        missingAttributes += 1
    if containsNumber == False:
        strength_score -= 5
        missingAttributes += 1
    if containsUppercase == False:
        strength_score -= 5
        missingAttributes += 1
    if containsLowercase ==False:
        strength_score -= 5
        missingAttributes += 1

    
    for repeat in password_char: # Checks to see if the characters of the password is identical
        if repeat != first_Char[0]:
            is_Identical = False

    if is_Identical:
        strength_score = 0 

    # print("-------------->",missingAttributes)
    if missingAttributes >=2: # Further Punishment if the password does not meet 2 of the password policies.
        strength_score -= 5

    if leak_check_status:
        is_leaked = leak_checker(password,filepath)
        if is_leaked:
            strength_score = 0


    # print("Password length:", password_length)
    # print("password in characters:", password_char)

    #########################################################
    #                Password Grading                       #
    #########################################################   

    if strength_score < 0:  #Sets the strength score to zero if in the negatives
        strength_score = 0

    printBreaker = 0
    for i in range(0,strength_score):
        if strength_score <=5:
            print(f"{RED}▆{RESET}", end="")
        elif (strength_score > 5) and (strength_score <=16):
            print(f"{YELLOW}▆{RESET}", end="")
        elif (strength_score > 16):
            print(f"{GREEN}▆{RESET}", end="")

        printBreaker += 1
        if printBreaker >= 30: #This stops the loop incase the password strength score is large
            break 
    if strength_score > 0 :
        print("")
    # print("")

    memory_score = "---"
    convenience_score = "---"
    security_score = "Low"

    if (password_length <= 8) or (strength_score == 0):
        
        memory_score = "Easy"
        if password_length <8:
            convenience_score = "High"
        elif (password_length>= 8) or (password_length <= 16):
            convenience_score = "Medium"
        else:
            convenience_score = "Low"
    elif (password_length>= 8) and (password_length <= 16):
        
        memory_score = "Medium"
        convenience_score = "Medium"
    elif  password_length > 16:
        
        memory_score = "Low"
        convenience_score = "Low"


        

    
    if strength_score == 0:
        print(f"{RED}▆{RESET}")
        print(f'{RED}WARNING:{RESET} Bad Password.')
        print(f'Security:{RED}     {security_score}{RESET}')
        print(f'Memorability: {memory_score}')
        print(f'Convenience:  {convenience_score}')

    elif (strength_score >=1) and (strength_score<=5):
        print(f'{RED}WARNING:{RESET} Bad Password.')
        print(f'Security:{RED}     {security_score}{RESET}')
        print(f'Memorability: {memory_score}')
        print(f'Convenience:  {convenience_score}')
    elif (strength_score > 5) and (strength_score < 16):
        security_score = "Medium"
        print(f'{YELLOW}Warning:{RESET} Weak Password.')
        print(f'Security:{YELLOW}     {security_score}{RESET}')
        print(f'Memorability: {memory_score}')
        print(f'Convenience:  {convenience_score}')

    else:
        security_score = "High"
        if strength_score > 30:
            security_score = "Excellent"
        if strength_score > 40:
            security_score = "Outstanding"
        print(f'{GREEN}Status:{RESET} Strong Password.')
        print(f'Security:{GREEN}     {security_score}{RESET}')
        print(f'Memorability: {memory_score}')
        print(f'Convenience:  {convenience_score}')

    print("")
    print("Password Strength Score: ", strength_score)



def leak_checker(password,filepath):
    try:
        with open(filepath,"r",encoding="latin-1") as file:
            for line in file:
                clean_line = line.strip()

                if password == clean_line:
                    print(f'{BLINK}{RED}SECURITY WARNING{RESET}: Password was found in a data leak.')
                    return True
        return False
    except FileNotFoundError:
        print(f'[{RED}SYSTEM ALERT{RESET}] File missing or could not be found. Skipping Password Leak program.')
        return False









program_loop = True
hidden_typing = False
wordlist_import = False
custom_list = False
default_wordlist_settings = 'disabled'
default_wordlist = "rockyou.txt"
leak_check_status = False

if __name__ == "__main__":

    print("Welcome to the Password Analyzer.")
    print("Please read the README file for tips.")
    print("Type 'exit' or 'quit' at any time to leave the program. \n")

    typing_settings = input("Enable hidden typing? (Y/N):  ")
    if typing_settings.lower() in ['exit', 'quit','q']:
        print("Closing Program...")
        program_loop = False
        raise SystemExit
    elif typing_settings.lower() in ['y', 'yes','yeah']:
        hidden_typing = True
        print("Your Password Typing is now Hidden.")
    elif typing_settings.lower() in ['n', 'no','nah']:
        print("Typed Passwords will be visible.")     
    else:
        print("Invalid Input. Typed Passwords will be visible.")         

    if hidden_typing:
        print("Preparing Privacy Tools...")
        import getpass #Reduces Shoulder Surfing Attacks


    #    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    #    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    #    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    #    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    
    wordlist_settings = input("Enable Global Leak Search? (Y/N):  ")
    if (wordlist_settings.lower() in ['exit', 'quit','q']) and (program_loop == True):
        print("Closing Program...")
        program_loop = False
        raise SystemExit
    elif wordlist_settings.lower() in ['y', 'yes','yeah']:
        wordlist_import = True
        leak_check_status = True
        print(f"[Status: {GREEN}Enabled{RESET}] Password Leak tool")
    elif wordlist_settings.lower() in ['n', 'no','nah']:
        print(f"[Status: {RED}DISABLED{RESET}] Password Leak tool")     
    else:
        print(f"Invalid Input. \n [Status: {RED}DISABLED{RESET}] Password Leak tool")    

    #    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    #    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    #    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    #    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+

    if wordlist_import:
        print("Preparing Password Lookup tools...")
        from pathlib import Path
        script_dir = Path(__file__).resolve().parent
        print("\n[Advanced Settings]:")
        default_wordlist_settings = input("Use Custom Word list?? (Y/N):  ")


    
    if (default_wordlist_settings.lower() in ['exit', 'quit','q']) and (program_loop == True):
        print("Closing Program...")
        program_loop = False
        raise SystemExit
    elif default_wordlist_settings.lower() in ['y', 'yes','yeah']:
        custom_list = True
    elif default_wordlist_settings.lower() in ['n', 'no','nah']:
        custom_list = False
        print(f"Using Default Wordlist.")     
    elif default_wordlist_settings.lower() in ['disabled']:
        program_loop = True
    else:
        print(f"Invalid Input. Using Default Wordlist.")    

    if wordlist_import and not custom_list:
        default_wordlist = script_dir / "rockyou.txt"
        print("The program will alert you if your password is found in a data leak")
    elif wordlist_import and custom_list:
        print("Please make sure your custom wordlist is in the same folder as the program.")
        user_list = str(input("What is the file name of the wordlist?(Include the file extension)     "))
        default_wordlist = script_dir / user_list

    #    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    #    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    #    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    #    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    
    while program_loop:

        session += 1

        if hidden_typing:
            user_password = str(getpass.getpass("[Hidden] Import your password for testing:     ")) # Reduces Shoulder Surfing Attacks
        else:
            user_password = str(input("Import your password for testing:     ")) # Grabs Password from Input
        

        if user_password.lower() in ['exit', 'quit','q']:
            print("Closing Program...")
            break
        if user_password == "":
            print("No Password was Entered. Password set to Password123")
            user_password = "Password123"
        
        password_Analytics(user_password,default_wordlist)
        print("+", end='')
        print("-----+" * 8, "(" + str(session) +")")




        
    
    


