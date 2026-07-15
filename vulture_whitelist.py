"""Vulture whitelist (#101): known false positives — NamedTuple / SQLModel / response
model fields that vulture reports as "unused variable" because it can't trace their
cross-module construction and attribute access. Regenerate with:
  uvx vulture app --min-confidence 60 --make-whitelist (plus the pyproject ignores)
after verifying each entry really is a used field, not genuinely dead code.
"""

risk_score_before  # unused variable (app/models.py:70)
first_seen  # unused variable (app/models.py:93)
last_seen  # unused variable (app/models.py:94)
type  # unused variable (app/routes/api.py:175)
added  # unused variable (app/routes/api.py:289)
duplicates  # unused variable (app/routes/api.py:290)
invalid  # unused variable (app/routes/api.py:291)
errors  # unused variable (app/routes/api.py:292)
deferred  # unused variable (app/routes/api.py:324)
duplicates  # unused variable (app/routes/api.py:325)
invalid  # unused variable (app/routes/api.py:326)
errors  # unused variable (app/routes/api.py:327)
popularity  # unused variable (app/scoring.py:25)
staleness  # unused variable (app/scoring.py:27)
code_behaviour  # unused variable (app/scoring.py:28)
