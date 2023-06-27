import hashlib


def hasher(text):
  '''
  Returns the sha1 hash of the given text
  '''
  hashed_text = hashlib.sha1(text.encode('utf-8')).hexdigest()
  return hashed_text

def crack_sha1_hash(hash, use_salts=False):
  '''
  Returns the text for a given sha1 hash based on the top 10,000 passwords and various known salts (use of salts is optional).
  '''

  library = {}
  passwords = []
  salts = []
  passwordFile = "top-10000-passwords.txt"
  saltFile = "known-salts.txt"

  with open(passwordFile, 'r') as file:
    for line in file:
      line = line.strip()
      passwords.append(line)
  
  with open(saltFile, 'r') as file:
    for line in file:
      line = line.strip()
      salts.append(line)

  # Optional salt section
  if use_salts:
    for password in passwords:
      for salt in salts:
        # Prepend salt
        hashed = hasher(salt + password)
        library[hashed] = password
        # Append salt
        hashed = hasher(password + salt)
        library[hashed] = password
  
  # Convert unsalted passwords (always)
  for password in passwords:
    hashed = hasher(password)
    library[hashed] = password

  # Either password found so hash is a key in the library or not which will result in an error
  try:
    return library[hash]
  except:
    return "PASSWORD NOT IN DATABASE"

#print("Password is: ", crack_sha1_hash('b1b3773a05c0ed0176787a4f1574ff0075f7521e')) # example print for qwerty