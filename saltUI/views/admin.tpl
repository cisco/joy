<!--
 *	
 * Copyright (c) 2016 Cisco Systems, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 * 
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
-->

% rebase('base.tpl', title='Page Title')

<script>
document.getElementById("navbar_admin").className = "active";
</script>

<!-- Main jumbotron for a primary marketing message or call to action -->
<h1 class="page-header">Local Analytics User Interface, 0.2a</h1>





<div class="col-lg-6 col-sm-6 col-12">
  % if flags != None:
    % if 'malware_splt' in flags:
      % if flags['malware_splt'] == True:
	<p style='color:green;'><span class="glyphicon glyphicon-ok" style='color:green;'></span>&nbsp;&nbsp;Malware SPLT Parameters Successfully Updated</p>
      % else:
        <p style='color:red;'><span class="glyphicon glyphicon-remove" style='color:red;'></span>&nbsp;&nbsp;Malware SPLT Parameters Update Failed</p>
      % end
    % end
    % if 'malware_bd' in flags:
      % if flags['malware_bd'] == True:
	<p style='color:green;'><span class="glyphicon glyphicon-ok" style='color:green;'></span>&nbsp;&nbsp;Malware BD Parameters Successfully Updated</p>
      % else:
        <p style='color:red;'><span class="glyphicon glyphicon-remove" style='color:red;'></span>&nbsp;&nbsp;Malware BD Parameters Update Failed</p>
      % end
    % end
  % end


  <form action="/update_malware">
    <table>
      <tr>
        <td><h4>Update Malware Classifier Parameters:</h4></td>
	<td>&nbsp;&nbsp;<input class="btn btn-primary" type="submit" value="Update"/></td>
      </tr>
    </table>
  </form>
</div>