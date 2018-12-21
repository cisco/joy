
% rebase('base.tpl', title='Upload File')

<ol class="breadcrumb">
  <li class="breadcrumb-item">
    <a href="/index">Dashboard</a>
  </li>
  <li class="breadcrumb-item active">Upload File</li>
</ol>

% rebase('base.tpl', title='Page Title')

<style>
.btn-file {
  position: relative;
  overflow: hidden;
}
.btn-file input[type=file] {
  position: absolute;
  top: 0;
  right: 0;
  min-width: 100%;
  min-height: 100%;
  font-size: 100px;
  text-align: right;
  filter: alpha(opacity=0);
  opacity: 0;
  background: red;
  cursor: inherit;
  display: block;
}
input[readonly] {
  background-color: white !important;
  cursor: text !important;
}
</style>


<script src="https://code.jquery.com/jquery-2.1.4.min.js"></script>
<script>
$(document).on('change', '.btn-file :file', function() {
  var input = $(this),
      numFiles = input.get(0).files ? input.get(0).files.length : 1,
      label = input.val().replace(/\\/g, '/').replace(/.*\//, '');
  input.trigger('fileselect', [numFiles, label]);
});
$(document).ready( function() {
    $('.btn-file :file').on('fileselect', function(event, numFiles, label) {
        
        var input = $(this).parents('.input-group').find(':text'),
            log = numFiles > 1 ? numFiles + ' files selected' : label;
        
        if( input.length ) {
            input.val(log);
        } else {
            if( log ) alert(log);
        }
        
    });
});
</script>


<div class="col-lg-6 col-sm-6 col-12">
<form action="/fingerprint/upload" method="post" enctype="multipart/form-data">
  <h4>Select PCAP file:</h4>
  <div class="input-group" style="margin-bottom:4px">
    <span class="input-group-btn">
      <span class="btn btn-primary btn-file" style="padding-right:24px; margin-right:5px;">
        Browse&nbsp;&hellip;&nbsp;&nbsp; <input type="file" name="upload">
      </span>
    </span>
    <input type="text" id="textfield" class="form-control" readonly>
  </div>
  <input class="btn btn-primary" type="submit" value="Start upload" />
</form>
</div>

