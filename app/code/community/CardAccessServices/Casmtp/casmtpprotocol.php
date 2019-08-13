<?php
/**
 * Card Access Services CASMTP
 *
 * Copyright 2012 Card Access Services
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author      Card Access Services
 * @copyright   Copyright (c) 2012 Card Access Services (http://www.cardaccess.com.au)
 * @license     http://opensource.org/licenses/Apache-2.0  Apache Software License (ASL 2.0)
 */

/**
 * This class implements exceptions which are pegged as CASMTP specific
 */
class CasmtpException extends Exception {
    /**
     * Constructor
     *
     * @param string  $message           the error message
     * @param string  $code              the error code (optional)
     * @param string  $previous          the previous exception (optional)
     *
     * @return void
     * @access public
     */
    public function __construct($message, $code = 0, Exception $previous = null) {
        /* We don't do much here */
        parent::__construct($message, $code, $previous);
    }
}

/**
 * This class implements parsing of the CASMTP transaction result
 */
class CasmtpTxnResult {
    /**
     * The scode
     *
     * @var string
     * @access private
     */
    private $_statusCode;

    /**
     * The response code
     *
     * @var string
     * @access private
     */
    private $_respCode;

    /**
     * Settlement date (YYMM)
     *
     * @var string
     * @access private
     */
    private $_setlDate;

    /**
     * Authorization code
     *
     * @var string
     * @access private
     */
    private $_authCode;

    /**
     * The request audit number
     *
     * @var string
     * @access private
     */
    private $_requestedAudit;

    /**
     * Diagnostic message
     *
     * @var string
     * @access private
     */
    private $_msg;

    /**
     * Constructor
     *
     * @param string  $message           error message
     * @param string  $code              error code (optional)
     * @param string  $previous          previous exception (optional)
     *
     * @return void
     * @access public
     */
    public function __construct($resp) {
        $this->_statusCode = CasmtpTxnResult::_getDe048Kvp ("CAS.RESPONSE.STATUSCODE", $resp);
        $this->_respCode = CasmtpTxnResult::_getKvp ("DE039", $resp);
        $this->_setlDate = CasmtpTxnResult::_getKvp ("DE015", $resp);
        $this->_authCode = CasmtpTxnResult::_getKvp ("DE038", $resp);
        $this->_requestedAudit = CasmtpTxnResult::_getDe048Kvp("CAS.RESPONSE.AUDIT1", $resp);
        $this->_msg = CasmtpTxnResult::_getDe048Kvp ("CAS.RESPONSE.MSG", $resp);
    }

    /**
     * Get the scode
     *
     * Typically blank, numeric (positive or negative)
     *
     * @return string  status code
     * @access public
     */
    public function getStatusCode() {
        return $this->_statusCode;
    }

    /**
     * Get the response code
     *
     * Typically blank or 2 characters
     *
     * @return string  response code
     * @access public
     */
    public function getResponseCode() {
        return $this->_respCode;
    }

    /**
     * Get the settlement date
     *
     * Typically blank or in YYMM format
     *
     * @return string   settlement date
     * @access public
     */
    public function getSettlementDate() {
        return $this->_setlDate;
    }

    /**
     *
     * Get the authorization code
     *
     * Format varies wildly, very bank specific, some banks insert trailing spaces (these are
     * considered normal and part of the auth code)
     *
     * @return string  authcode
     * @access public
     */
    public function getAuthorizationCode() {
        return $this->_authCode;
    }

    /**
     *
     * Get the requested audit number
     *
     * NB: This field is only filled in when a new audit number is requested. It is possible to
     * piggyback an audit number request onto a transaction operation (but the sample code doesn't
     * take advantage of this)
     *
     * @return string  the requested audit number
     * @access public
     */
    public function getRequestedAuditNumber() {
        return $this->_requestedAudit;
    }

    /**
     * Diagnostic message
     *
     * Common for it to be blank if casmtp doesn't want to add any additional commentary. This
     * message is intended for developers only, it may be confusing or make no sense if exposed
     * to an end user
     *
     * @return string  diagnostic message
     * @access public
     */
    public function getDiagnosticMessage() {
        return $this->_msg;
    }

    /**
     * Whether the transaction was approved
     *
     * @return boolean  if the transaction was approved
     * @access public
     */
    public function isApproved() {
        return ($this->_statusCode === "0") && in_array ($this->_respCode, array ("00", "08", "10", "11", "16", "77"));
    }

    /**
     * Whether the transaction was not approved and not a normal decline (e.g. a time out)
     *
     * @return boolean  if the transaction was not approved and not a normal decline (e.g. a time out)
     * @access public
     */
    public function isAbnormalResult() {
        return $this->_statusCode !== "0";
    }

    /**
     * Utility method to retrieve value from the main KVPs
     *
     * @return string  KVP value
     * @access private
     */
    private static function _getKvp($key, $kvp_array, $default = "") {
        if (!array_key_exists($key, $kvp_array))
            return $default;
        else
            return $kvp_array[$key];
    }

    /**
     * Utility method to retrieve value from the "miscellaneous" KVPs
     *
     * @return string  KVP value
     * @access public
     */
    private static function _getDe048Kvp($key, $kvp_array) {
        return CasmtpTxnResult::_getKvp($key, CasmtpTxnResult::_getKvp("DE048", $kvp_array, array()));
    }
}

/**
 * This class implements the casmtp proxy parameters
 *
 * NB: There is no online validation performed
 */
class CasmtpProxy {
    /**
     * Proxy server
     *
     * @var string
     * @access private
     */
    private $_server;
    
    /**
     * Proxy server
     *
     * @var string
     * @access private
     */
    private $_login;
    
    /**
     * Constructor
     *
     * @param string  $proxyHost         proxy host
     * @param string  $proxyPort         proxy port
     * @param string  $proxyUsername     proxy username
     * @param string  $proxyPassword     proxy password
     *
     * @return void
     * @access public
     */
    public function __construct($host = "", $port = "", $username = "", $password = "") {
        /* Set defaults */
        $this->_server = "";
        $this->_login = "";

        /* Set server if present */
        if (!empty($host)) {
            if (empty($port)) {
                $port = "8080";
            }
            else {
                if (!is_numeric($port)) {
                    throw new CasmtpException("Proxy port must be numeric, please check your configuration");
                }
            }
            /* As per RFC 1123; we are actually a bit too loose, but this is ok as this is an admin only setting */
            if (strpos($host, ':') !== FALSE) {
                throw new CasmtpException("Proxy host is not allowed to contain a colon, please check your configuration");
            }
            $this->_server = $host . ':' . $port;
        }
        else {
            if (!empty($port)) {
                throw new CasmtpException("Proxy port has been specified, but host name was left empty, please check your configuration");
            }
        }

        /* Set login if present */
        if (!empty($username)) {
            if (empty($this->_server)) {
                throw new CasmtpException("Proxy login specified but the host was left empty, please check your configuration");
            }
            if (empty($password)) {
                $password = "";
            }
            /* As per RFC 2068 */
            if (strpos($username, ':') !== FALSE) {
                throw new CasmtpException("Proxy username is not allowed to contain a colon, please check your configuration");
            }
            $this->_login = $username . ':' . $password;
        }
        else {
            if (!empty($password)) {
                throw new CasmtpException("Proxy password has been specified, but username was left empty, please check your configuration");
            }
        }
    }

    /**
     * Get the proxy server
     *
     * @return string  proxy server
     * @access public
     */
    public function getServer() {
        return $this->_server;
    }

    /**
     * Get the proxy login
     *
     * @return string  proxy login
     * @access public
     */
    public function getLogin() {
        return $this->_login;
    }
}

/**
 * This class implements the request portion of the CASMTP protocol
 *
 * Currently only purchases and refunds are implemented - for other methods such as preauth, completion,
 * card present transactions etc, see the CASMTP userguide
 */
class Casmtp {
    /**
     * The gateway URL
     *
     * @var string
     * @access private
     */
    private $_targetUrl;

    /**
     * The ETX merchant ID
     *
     * @var string
     * @access private
     */
    private $_merchantId;

    /**
     * The hash key
     *
     * @var string
     * @access private
     */
    private $_hashKey;
    
    /**
     * The proxy server
     *
     * @var string
     * @access private
     */
    private $_proxy;

    /**
     * The live gateway URL
     *
     * @var string
     * @access public
     * @const
     */
    const LIVE_URL = 'https://etx.cardaccess.com.au/casmtp/casmtp.php';

    /**
     * The test gateway URL
     *
     * @var string
     * @access public
     * @const
     */
    const TEST_URL = 'https://etx.cardaccess.com.au/casmtp/testcasmtp.php';
    
    /**
     * The default HTTP timeout
     *
     * @var string
     * @access public
     * @const
     */
    const DEFAULT_HTTPS_TIMEOUT = 120;

    /**
     * Constructor
     *
     * @param string  $targetUrl         URL of the gateway (typically LIVE_URL or TEST_URL)
     * @param string  $proxy             Proxy server
     * @param string  $merchantId        ETX merchant ID, as assigned by Card Access Services
     * @param string  $hashKey           hash key, as assigned by Card Access Services
     *
     * @return void
     * @access public
     */
    public function __construct($targetUrl, $proxy, $merchantId, $hashKey) {
        $this->_targetUrl = $targetUrl;
        $this->_proxy = $proxy;
        $this->_merchantId = $merchantId;
        $this->_hashKey = $hashKey;
    }

    /**
     * Retrieve an audit number from the gateway
     *
     * An audit number is required before performing most operations. It is always safe to get
     * another audit number if the first request timed out etc
     *
     * @return string  audit number
     * @access public
     */
    public function getAudit() {
        /* Send off the request */
        $kvps = array('CAS.REQUEST.AUDIT' => '1');
        $resp = $this->_sendRequest(
            array(
                'dataformat' => 'HTTP_AS2805',
                'DE001' => '0800',
                'DE042' => $this->_getFormattedMerchantId()
            ),
            $kvps,
            $this->_hashKey
        );

        /* Try to get at the audit number */
        $result = new CasmtpTxnResult($resp);
        $audit = $result->getRequestedAuditNumber();

        /* Throw an exception if no audit number is present */
        if ($audit == "" or $audit == "-1") {
            $result = new CasmtpTxnResult($resp);
            throw new CasmtpException ($result->getDiagnosticMessage());
        }

        /* Return the audit number for use in a follow up transaction */
        return $audit;
    }

    /**
     * Make a purchase
     *
     * Each purchase must be made against a unique audit number. While the customer reference
     * is optional it is highly recommended. CVV is also optional, although banks may declined
     * transactions sent without a CVV
     *
     * @param string  $audit             audit number retrieved using $this->getAudit()
     * @param string  $pan               credit card number
     * @param string  $expiry            expiry date in YYMM format
     * @param string  $cvv               card verification value
     * @param string  $amt               amount, in the minor denomination of the merchant account
     * @param string  $custRef           customer reference field. Appears in the MMI reports
     *
     * @return void
     * @access public
     */
    public function purchase($audit, $pan, $expiry, $cvv, $amt, $custref = "") {
        /* Send the request */
        $kvps = array('CAS.AUDIT' => $audit);
        if (!empty($custref)) {
            $kvps['CAS.CUSTREF'] = $custref;
        }
        if (!empty($cvv)) {
            $kvps['CAS.CARD.CVC'] = $cvv;
        }
        $resp = $this->_sendRequest(
            array(
                'dataformat' => 'HTTP_AS2805',

                'DE001' => '0200',
                'DE003' => '003000',

                'DE042' => $this->_getFormattedMerchantId(),

                'DE002' => $pan,
                'DE014' => $expiry,
                'DE004' => sprintf("%d", $amt)
            ),
            $kvps,
            $this->_hashKey
        );

        /* Interpret the request */
        return new CasmtpTxnResult($resp);
    }

    /**
     * Refund a prior transaction
     *
     * Each refund must be made against a unique audit number. The audit number of the transaction
     * to refund will also be required.
     *
     * We have encountered some banks in the past who do NOT allow merchants to perform refunds - if
     * this is the case then the CASMTP refund operation will be rejected by the bank
     *
     * @param string  $audit             audit number retrieved using $this->getAudit()
     * @param string  $audit_to_refund   audit number of transaction to refund
     * @param string  $amt               amount to refund, in the minor denomination of the merchant account
     * @param string  $custRef           customer reference field. Appears in the MMI reports
     *
     * @return void
     * @access public
     */
    public function refund($audit, $audit_to_refund, $amt, $custref = "") {
        /* Send request */
        $kvps = array('CAS.AUDIT' => $audit, 'CAS.REFUNDAUDIT' => $audit_to_refund);
        if (!empty($custref))
            $kvps['CAS.CUSTREF'] = $custref;
        $resp = $this->_sendRequest(
            array(
                'dataformat' => 'HTTP_AS2805',

                // Refund method    
                'DE001' => '0200',
                'DE003' => '200030',

                'DE042' => $this->_getFormattedMerchantId(),

                'DE004' => sprintf("%d", $amt)
            ),
            $kvps,
            $this->_hashKey
        );

        /* Interpret result */
        return new CasmtpTxnResult($resp);
    }

    /**
     * Parses a transaction response into an array
     *
     * @param string  $lines             raw response text from CASMTP
     * @param string  $lineSep           line separator to use
     * @param string  $kvpSep            kvp separator to use
     *
     * @return array  response kvps
     * @access private
     */
    private static function _explodeKvps($lines, $lineSep, $kvpSep) {
        $resp = array();
        $lines = explode($lineSep, $lines);
        foreach ($lines as $line) {
            $kvp = explode($kvpSep, $line, 2);
            if (count($kvp) != 2)
                continue;
            $key = $kvp[0];
            $value = $kvp[1];
            $resp[$key] = $value;
        }
        return $resp;
    }

    /**
     * Encode a specific DE048 KVP for use in the hash calculation
     *
     * @param string  $key               key name
     * @param string  $value             key value
     *
     * @return string  the encoded DE048 KVP value
     * @access private
     */
    private static function _encodeDe048KvpForHash($key, $value) {
        return $key . urlencode('=') . base64_encode($value);
    }

    /**
     * Encode a specific DE048 KVP for use in the post
     *
     * @param string  $key               key name
     * @param string  $value             key value
     *
     * @return string  the encoded DE048 KVP value
     * @access private
     */
    private static function _encodeDe048KvpForPost($key, $value) {
        return $key . '=' . base64_encode($value);
    }

    /**
     * Encode the entire DE048 KVP for use in the hash calculation
     *
     * @param string  $de048             DE048 array
     *
     * @return string  the encoded DE048 value
     * @access private
     */
    private static function _encodeDe048ForHash($de048) {
        return array("DE048" => implode(urlencode ('&'), array_map('Casmtp::_encodeDe048KvpForHash', array_keys($de048), array_values($de048))));
    }

    /**
     * Encode the entire DE048 KVP for use in the post
     *
     * @param string  $de048             DE048 array
     *
     * @return string  the encoded DE048 value
     * @access private
     */
    private static function _encodeDe048ForPost($de048) {
        return array("DE048" => implode('&', array_map('Casmtp::_encodeDe048KvpForPost', array_keys($de048), array_values($de048))));
    }

    /**
     * Send a CASMTP request
     *
     * @param string  $postFieldsWithoutDe048   main post fields
     * @param string  $de048                    supplementary post fields
     *
     * @return void
     * @access private
     */
    private function _sendRequest($postFieldsWithoutDe048, $de048)
    {
        /* POST fields for transaction */
        $postFieldsForPost = array_merge($postFieldsWithoutDe048, Casmtp::_encodeDe048ForPost($de048));

        /* Insert hash */
        $this->_insertHash($postFieldsForPost, $postFieldsWithoutDe048, $de048);

        /* Encode POST data */
        $postData = http_build_query($postFieldsForPost);

        /* Do POST */
        /*
        $opts = array(
            'http' =>
                array(
                    'method'  => 'POST',
                    'header'  => 'Content-type: application/x-www-form-urlencoded',
                    'content' => $postData
                )
        );
        $context = stream_context_create($opts);
        $lines = file_get_contents($this->_targetUrl, false, $context);
        */

        /* CURL method */
        $crl = curl_init();

        /* Specify URL + automatically follow redirects */
        curl_setopt($crl, CURLOPT_URL, $this->_targetUrl);
        curl_setopt($crl, CURLOPT_FOLLOWLOCATION, 1);

        /* Specify POST data + indicate we want the response back for processing */
        curl_setopt($crl, CURLOPT_POST, 1);
        curl_setopt($crl, CURLOPT_POSTFIELDS, $postData);
        curl_setopt($crl, CURLOPT_RETURNTRANSFER, 1);

        /* Make sure we always use a fresh connection */
        curl_setopt($crl, CURLOPT_FORBID_REUSE, 1);
        curl_setopt($crl, CURLOPT_FRESH_CONNECT, 1);

        /* Make sure we specify a sane timeout */
        curl_setopt($crl, CURLOPT_CONNECTTIMEOUT, Casmtp::DEFAULT_HTTPS_TIMEOUT);
        curl_setopt($crl, CURLOPT_TIMEOUT, Casmtp::DEFAULT_HTTPS_TIMEOUT);

        /* Specify proxy, if required */
        $proxyServer = $this->_proxy->getServer();
        if (!empty($proxyServer)) {
            curl_setopt($crl, CURLOPT_HTTPPROXYTUNNEL, true);
            curl_setopt($crl, CURLOPT_PROXY, $proxyServer);
            $proxyLogin = $this->_proxy->getLogin();
            if (!empty($proxyLogin)) {
                curl_setopt($crl, CURLOPT_PROXYUSERPWD, $proxyLogin);
            }
        }

        /* Send POST */
        $lines = curl_exec($crl);

        /* Check the result */
        $err = curl_errno($crl);
        if ($err != CURLE_OK) {
            throw new CasmtpException("CURL error performing transaction: " . curl_error($crl));
        }
        $status = curl_getinfo($crl, CURLINFO_HTTP_CODE);
        if ($status != '200') {
            throw new CasmtpException("HTTP error performing transaction: " . $status);
        }

        /* Decode main key value pairs */
        $resp = Casmtp::_explodeKvps($lines, "\n", "=");

        /* Further decode DE048 which has its own key value pairs (also base 64 encoded) */
        if (array_key_exists("DE048", $resp)) {
            /* Decode DE048 */
            $items = Casmtp::_explodeKvps($resp["DE048"], "&", "=");
            $resp["DE048"] = array ();
            foreach ($items as $key=>$value) {
                $resp["DE048"][$key] = base64_decode($value);
            }
        }
        else {
            /* Make sure DE048 always exists, even if it's just empty */
            $resp["DE048"] = array();
        }

        /* Finalized response */
        return $resp;
    }

    /**
     * Insert hash value into the request
     *
     * NB: The time stamp of the server machine is embedded into the hash value. This value is checked
     * by CASMTP - make sure your server clock is set correctly!
     *
     * @param string  $destFields            the destination for the hash KVPs
     * @param string  $postFields            main post fields
     * @param string  $de048                 supplementary post fields
     *
     * @return void
     * @access private
     */
    private function _insertHash(&$destFields, $postFields, $de048) {
        $postFields_for_hash = array_merge($postFields, Casmtp::_encodeDe048ForHash($de048));

        /* Insert the current UTC timestamp */
        $timestamp = gmdate("Y/m/d G:i:s");
        $destFields["CAS_SECURITY_TIMESTAMP"] = $timestamp;
        $postFields_for_hash["CAS_SECURITY_TIMESTAMP"] = $timestamp;

        /* Make sure the post fields are appended in the correct order */
        $request_keys = array_keys($postFields_for_hash);
        asort($request_keys);

        /* Concatenate all the post fields together */
        $temp_str = "";
        foreach ($request_keys as $k) {
            $v = $postFields_for_hash[$k];
            if ($temp_str != "")
                $temp_str .= "&";
            $temp_str .= ($k . "=" . $v);
        }

        /* Calculate the hash */
        $hash_value = hash_hmac("sha256", $temp_str, $this->_hashKey);
        $destFields["CAS_SECURITY_TYPE"] = "Hash";
        $destFields["CAS_SECURITY_VALUE"] = $hash_value;
    }

    /**
     * Format the merchant ID for use in a CASMTP request
     *
     * @return string  formatted merchant ID
     * @access private
     */
    private function _getFormattedMerchantId() {
        return str_pad($this->_merchantId, 15, "0", STR_PAD_LEFT);
    }
}
