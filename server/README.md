# Как запустить сервак

1. Ctrl(Cmd) + Shift + P ---> Python: Create Enviromenent...
2. Устанавливаем зависимости из `requirements.txt`
3. В консольке заходим в папку `server`
4. Пишем `python -m  unvicorn main:app --reload`
5. Переходим в [127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) и наблюдаем свагер


# Перенос файлов

`scp -r ./server p1111@62.84.122.18:/home/p1111/server`