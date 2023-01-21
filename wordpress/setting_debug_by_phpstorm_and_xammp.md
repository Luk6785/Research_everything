# Cài đặt debug với phpstorm và xammp với xdebug trên windows

#### Bước 1
- Tạo phpinfo.
- Copy phpinfo vào trang web https://xdebug.org/wizard nó sẽ cho biết mình cần thiếu cái gì.
```js
But here are the instructions anyway:
Download php_xdebug-3.1.6-7.4-vc15-x86_64.dll
Move the downloaded file to C:\xampp\php\ext, and rename it to php_xdebug.dll
Update C:\xampp\php\php.ini to have the line:
zend_extension = xdebug
Restart the Apache Webserver
```
- Khi nào mà phpinfo chứa xdebug là thành công.
- Cài thêm xdebug extension trên chrome nữa.
#### Bước 2
- Cài đặt tại php.ini
```js
[XDebug]
zend_extension=C:\xampp\php\ext\php_xdebug_phpstorm.dll
xdebug.mode=debug
xdebug.client_host=127.0.0.1
xdebug.client_port="9003"
```
- Port mặc định của PHPSTORM là 9000, 9003.
- Reset lại xammp rồi debug là được.


