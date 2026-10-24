<?php
// 模拟站点首页：普通的企业站页面，使用 session 记录访问次数。
session_start();
$_SESSION['visits'] = ($_SESSION['visits'] ?? 0) + 1;
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>Example Corp - 演示站</title></head>
<body>
  <h1>Example Corp</h1>
  <p>这是第 <?php echo (int)$_SESSION['visits']; ?> 次访问。</p>
  <p><a href="/upload.php">上传文件</a></p>
</body>
</html>
