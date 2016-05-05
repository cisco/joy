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

<br />

<script>
document.getElementById("navbar_home").className = "active";
</script>

<div class="col-md-14">
  <h4>Percentage of TLS flows with a RECOMMENDED selected ciphersuite: 
<a href="/scs/RECOMMENDED">{{perc_rec_scs}}</a></h4>
</div>

<div class="col-md-14">
  <h4>Percentage of TLS flows with a LEGACY selected ciphersuite: 
<a href="/scs/LEGACY">{{perc_leg_scs}}</a></h4>
</div>

<div class="col-md-14">
  <h4>Percentage of TLS flows with an AVOID selected ciphersuite: 
<a href="/scs/AVOID">{{perc_avo_scs}}</a></h4>
</div>

<br />
<br />

<div class="col-md-14">
  <h4>Percentage of non-TLS flows with high entropy: 
<a href="/high_entropy">{{be_perc}}</a></h4>
</div>
