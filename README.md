## Uruchamianie 

Aby uruchomić aplikację wymagany jest **python3**.
Potrzebny jest moduł pipenv. Można go zainstalować poprzez wpisanie w terminalu 

```
pip3 install pipenv 
```

Następnie upewnić się że naszym working dir jest folder z projektem i uruchomić:
```
pipenv install
pipenv shell
```
Następnie wystarczy wpisać:
```
flask run
```

## Uwaga https nie będzie działać na localhoscie. 

W celu obejrzenia strony działającej w środowisku produkcyjnym proszę o wejście pod ten adresem https://flask-secure-webapp.herokuapp.com/