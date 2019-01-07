<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta name="description" content="">
  <meta name="author" content="">
  <title>TLS Client Fingerprinting</title>
  <!-- Bootstrap core CSS-->
  <link href="/static/css/bootstrap.min.css" rel="stylesheet">
  <!-- Custom fonts for this template-->
  <link href="/static/css/font-awesome.min.css" rel="stylesheet" type="text/css">
  <!-- Page level plugin CSS-->
  <link href="/static/css/dataTables.bootstrap4.css" rel="stylesheet">
  <!-- Custom styles for this template-->
  <link href="/static/css/sb-admin.css" rel="stylesheet">
  <!-- DLP/ETA custom template-->
  <link href="/static/css/dlp_eta.css" rel="stylesheet">


</head>

<body class="fixed-nav sticky-footer bg-dark" id="page-top">
  <!-- Navigation-->
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top" id="mainNav">
    <a class="navbar-brand" href="/index">TLS Client Fingerprinting as a Service</a>
    <button class="navbar-toggler navbar-toggler-right" type="button" data-toggle="collapse" data-target="#navbarResponsive" aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarResponsive">

      <ul class="navbar-nav navbar-sidenav" id="exampleAccordion">
        <li class="nav-item" data-toggle="tooltip" data-placement="right" title="Dashboard">
          <a class="nav-link" href="/index">
            <i class="fa fa-fw fa-dashboard"></i>
            <span class="nav-link-text">Dashboard</span>
          </a>
        </li>
        <li class="nav-item" data-toggle="tooltip" data-placement="right" title="Fingerprint">
          <a class="nav-link" href="/fingerprint">
            <i class="fa fa-fw fa-area-chart"></i>
            <span class="nav-link-text">Fingerprint</span>
          </a>
        </li>
        <li class="nav-item" data-toggle="tooltip" data-placement="right" title="Upload">
          <a class="nav-link" href="/upload">
            <i class="fa fa-fw fa-table"></i>
            <span class="nav-link-text">Upload</span>
          </a>
        </li>
      </ul>

      <ul class="navbar-nav sidenav-toggler">
        <li class="nav-item">
          <a class="nav-link text-center" id="sidenavToggler">
            <i class="fa fa-fw fa-angle-left"></i>
          </a>
        </li>
      </ul>
    </div>
  </nav>
  <div class="content-wrapper">
    <div class="container-fluid">

      {{!base}}

    </div>
    <!-- /.container-fluid-->
    <!-- /.content-wrapper-->
    <footer class="sticky-footer">
      <div class="container">
        <div class="text-center">
          <small>Proof-of-Concept Web UI by Blake Anderson (blake.anderson@cisco.com)</small>
        </div>
      </div>
    </footer>
    <!-- Scroll to Top Button-->
    <a class="scroll-to-top rounded" href="#page-top">
      <i class="fa fa-angle-up"></i>
    </a>

    <!-- Bootstrap core JavaScript-->
    <script src="/static/js/jquery.min.js"></script>
    <script src="/static/js/bootstrap.bundle.min.js"></script>

    <!-- Core plugin JavaScript-->
    <script src="/static/js/jquery.easing.min.js"></script>
    <!-- Page level plugin JavaScript-->
    <script src="/static/js/Chart.min.js"></script>
    <script src="/static/js/jquery.dataTables.js"></script>
    <script src="/static/js/dataTables.bootstrap4.js"></script>
    <!-- Custom scripts for all pages-->
    <script src="/static/js/sb-admin.min.js"></script>
    <!-- Custom scripts for this page-->
    <script src="/static/js/sb-admin-datatables.min.js"></script>
    <script src="/static/js/sb-admin-charts.min.js"></script>

  </div>
</body>

</html>
