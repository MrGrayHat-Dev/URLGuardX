import pandas as pd

# -------------------------
# LOAD DATA
# -------------------------

phishtank = pd.read_csv("data/phishtank.csv")
openphish = pd.read_csv("data/openphish.txt", header=None)
majestic = pd.read_csv("data/majestic.csv")

# -------------------------
# FORMAT DATA
# -------------------------

# BAD URLs
bad1 = phishtank[['url']].rename(columns={'url': 'URL'})
bad2 = openphish.rename(columns={0: 'URL'})

bad = pd.concat([bad1, bad2])
bad['Label'] = 'Bad'

# GOOD URLs
majestic['URL'] = "http://" + majestic['Domain']
good = majestic[['URL']]
good['Label'] = 'Good'

# -------------------------
# CLEAN DATA
# -------------------------

def clean(df):
    df = df.dropna()
    df = df.drop_duplicates()
    df['URL'] = df['URL'].str.strip()
    df = df[df['URL'].str.startswith("http")]
    return df

bad = clean(bad)
good = clean(good)

# -------------------------
# BALANCE DATASET
# -------------------------

size = min(len(bad), len(good))

bad = bad.sample(size, random_state=42)
good = good.sample(size, random_state=42)

df = pd.concat([bad, good])
df = df.sample(frac=1).reset_index(drop=True)

df.to_csv("final_dataset.csv", index=False)

print("✅ Dataset ready:", df.shape)