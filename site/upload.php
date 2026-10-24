<?php
// 模拟站点上传页：使用 session.upload_progress 显示进度，是本漏洞的触发面之一。
session_start();
$uploaded = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['f'])) {
    $uploaded = $_FILES['f']['name'] . ' (' . (int)$_FILES['f']['size'] . ' bytes)';
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>上传文件 - Example Corp</title></head>
<body>
  <h1>上传文件</h1>
  <?php if ($uploaded !== null): ?>
    <p>已接收：<?php echo htmlspecialchars($uploaded, ENT_QUOTES, 'UTF-8'); ?></p>
  <?php endif; ?>
  <form method="post" enctype="multipart/form-data" action="/upload.php">
    <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="upload1">
    <input type="file" name="f">
    <button type="submit">上传</button>
  </form>
</body>
</html>
