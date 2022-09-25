## Checkboxes

- [X] Updated fsociety
- [ ] Issue does not already exist
- [X] fsociety issue, not a tool issue

--Updated Fsociety imports with new ones

--Line 184/185 in fsociety.py has an issue :

## Expected Result

```bash
        elif choice == "99":
            with open(configFile, 'wb') as configfile:
                config.write(configfile)
            sys.exit()
```
Should be writing to the config file
## Actual Result
Throws this error in console :
```bash
TypeError: a bytes-like object is required, not 'str'
```

