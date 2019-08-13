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

/* Load our CASMTP utility classes */
require_once('CardAccessServices/Casmtp/casmtpprotocol.php');
require_once('CardAccessServices/Casmtp/casmiscutil.php');

/**
 * Implements the gateway extension for transaction processing via the CASMTP method
 */
class CardAccessServices_Casmtp_Model_PaymentMethod extends Mage_Payment_Model_Method_Cc {
    /**
     * Unique payment identifier
     *
     * @var string
     * @access protected
     */
    protected $_code = 'casmtp';

    /**
     * Whether we are a gateway extension
     *
     * @var boolean 
     * @access protected
     */
    protected $_isGateway = true;

    /**
     * Whether we support the Authorize operation
     *
     * @var boolean 
     * @access protected
     */
    protected $_canAuthorize            = false;

    /**
     * Whether we support the Capture operation
     *
     * @var boolean 
     * @access protected
     */
    protected $_canCapture              = true;

    /**
     * Whether we support the CapturePartial operation
     *
     * @var boolean 
     * @access protected
     */
    protected $_canCapturePartial       = true;

    /**
     * Whether we support the Void operation
     *
     * @var boolean 
     * @access protected
     */
    protected $_canVoid                 = false;

    /**
     * Whether this extension can be used by cardholders during checkout
     *
     * @var boolean 
     * @access protected
     */
    protected $_canUseCheckout          = true;

    /**
     * Whether this extension can be used by the admin interface
     *
     * @var boolean 
     * @access protected
     */
    protected $_canUseInternal          = true;

    /**
     * Whether this extension can be used for multiple shipping
     *
     * @var boolean 
     * @access protected
     */
    protected $_canUseForMultishipping  = true;

    /**
     * Whether this extension can be used for saving credit cards
     *
     * This is not in the base module, but for some reason most of the other payment methods
     * declare it, so we'll do the same here just to be safe
     *
     * @var boolean 
     * @access protected
     */
    protected $_canSaveCc               = false;

    /**
     * Whether we can do a refund
     *
     * @return boolean  whether we can do a refund
     * @access private
     */
    public function canRefund() {
        $version = Mage::getVersionInfo();
        $major = intval ($version['major']);
        $minor = intval ($version['minor']);
        if ($major > 1) {
            return true;
        }
        else if ($major == 1) {
            return $minor > 5;
        }
        else {
            return false;
        }
    }

    /**
     * Whether we can do a partial refund
     *
     * @return boolean  whether we can do a partial refund
     * @access private
     */
    public function canRefundPartialPerInvoice() {
        return $this->canRefund();
    }

    /**
     * Get the specified configuration value
     *
     * @param string  $key               name of the key
     *
     * @return string  the configuration value
     * @access private
     */
    private function _getConfig($key) {
        return Mage::getStoreConfig("payment/casmtp/" . $key);
    }

    /**
     * Get the merchant ID from the user configuration
     *
     * @return string  the merchant ID
     * @access private
     */
    private function _getMerchantId() {
        return $this->_getConfig("etx_merchant");
    }

    /**
     * Get the hash key from the user configuration
     *
     * @return string  the hash key
     * @access private
     */
    private function _getHashKey() {
        return $this->_getConfig("hash_auth");
    }

    /**
     * Figure out the gateway URL from the user configuration
     *
     * @return string  the gateway URL
     * @access private
     */
    private function _getUrl() {
        return $this->_getConfig('is_test')? Casmtp::TEST_URL: Casmtp::LIVE_URL;
    }

    /**
     * Whether to log events into the system log file
     *
     * NB: If this is a high volume site then you will either want to turn this setting off or
     * ensure log rotation is being used
     *
     * @return boolean  whether to log events
     * @access private
     */
    private function _getLogEvents() {
        return $this->_getConfig('log_events');
    }

    /**
     * Create a new preconfigured CASMTP proxy instance
     *
     * @return string  the CASMTP proxy instance
     * @access private
     */
    private function _createCasmtpProxy() {
        try {
            return new CasmtpProxy($this->_getConfig('proxy_server_host'), $this->_getConfig('proxy_server_port'), $this->_getConfig('proxy_login_username'), Mage::helper('core')->decrypt($this->_getConfig('proxy_login_password')));
        }
        catch (Exception $e) {
            Mage::log("$this->_code: proxy misconfigured");
            Mage::throwException(Mage::helper('casmtp')->__($e->getMessage()));
        }
    }

    /**
     * Create a new preconfigured CASMTP instance
     *
     * @return string  the CASMTP instance
     * @access private
     */
    private function _createCasmtp() {
        return new Casmtp($this->_getUrl(), $this->_createCasmtpProxy(), $this->_getMerchantId(), Mage::helper('core')->decrypt($this->_getHashKey()));
    }

    /**
     * Log the event
     *
     * @return void
     * @access private
     */
    private function _logPaymentEvent($payment, $msg) {
        if ($this->_getLogEvents()) {
            $cust_ref = CasMiscUtil::getCustRefFromPayment($payment);
            Mage::log($this->_code . "[" . $cust_ref . "]:" . $msg);
        }
    }

    /**
     * Retrieve audit number
     *
     * @param string  $casmtp            casmtp instance
     * @param string  $payment           payment instance
     * @param string  $record_audit      whether to record the audit number
     *
     * @return void
     * @access private
     */
    private function _getAuditNumber($casmtp, $payment, $record_audit = true) {
        $cust_ref = CasMiscUtil::getCustRefFromPayment($payment);

        /* Get the audit number, this is used to trace the transaction */
        $this->_logPaymentEvent($payment, "getting audit number for order");
        try {
            $audit = $casmtp->getAudit();
        }
        catch (Exception $e) {
            /*
             * This almost always indicates a misconfiguration issue
             *
             * But on the up side no transaction has gone to the bank, so it is always safe to retry. Note that
             * the error message from the exception is probably more confusing the end user than helpful, so we
             * do not expose this (although we do log it)
             */
            $this->_logPaymentEvent($payment, "error encountered: " . $e->getMessage());
            Mage::throwException(Mage::helper('casmtp')->__("Error attempting transaction - please try again later"));
        }

        /*
         * Record the audit number against the payment, if specified
         *
         * This can be quoted during support calls
         */
        $this->_logPaymentEvent($payment, "got audit number $audit");
        if ($record_audit) {
            /* Fill in the transaction ID */
            $payment->setCcTransId($audit);
            //$payment->setLastTransId($audit);
            $payment->setTransactionId($audit);
        }

        return $audit;
    }

    /**
     * Interpret the transaction result
     *
     * @param string  $result            the CASMTP transaction result
     * @param string  $payment           payment instance
     *
     * @return void
     * @access private
     */
    private function _interpretTxnResult ($result, $payment) {
        $cust_ref = CasMiscUtil::getCustRefFromPayment($payment);

        /* Log the payment event for the benefit of debugging */
        $this->_logPaymentEvent($payment, "scode = " . $result->GetStatusCode());
        $this->_logPaymentEvent($payment, "rcode = " . $result->GetResponseCode());
        $this->_logPaymentEvent($payment, "setl_date = " . $result->GetSettlementDate());
        $this->_logPaymentEvent($payment, "auth_code = " . $result->GetAuthorizationCode());
        $this->_logPaymentEvent($payment, "err_msg = " . $result->GetDiagnosticMessage());

        /* Figure out the result */
        if ($result->isApproved()) {
            /* Hooray, transaction approved */
            $this->_logPaymentEvent($payment, "transaction approved");
        }
        else {
            /*
             * Generate the error message
             *
             * We keep it in general terms to avoid confusing the end user - the real error and
             * all relevant scodes etc have already been logged above for the administrator to inspect
             */
            $errmsg = $result->isAbnormalResult()? "An error ocurred during transaction processing - please contact your site administrator for more details": "The transaction was declined - please try again with a different credit card";
            $this->_logPaymentEvent($payment, "displayed message = " . $errmsg);
            Mage::throwException(Mage::helper('casmtp')->__($errmsg));
        }
    }

    /**
     * Validate the configuration
     *
     * This method is the only one where we expose inner configuration details - presumably the administrator
     * will run through a test transaction to make sure all is configured before unleashing it to the internet!
     *
     * @return void
     * @access public
     */
    public function validate() {
        /* Let the parent do it's usual validation */
        parent::validate ();

        /* Check the ETX merchant ID is present and numeric */
        $merid = $this->_getMerchantId();
        if (!is_numeric($merid)) {
            Mage::log("$this->_code: merchant ID misconfigured as $merid");
            Mage::throwException(Mage::helper('casmtp')->__('The "ETX Merchant ID" configuration value is not numeric, please set this to the value assigned by Card Access Services'));
        }

        /* Check the hash key is present */
        $hash_key = $this->_getHashKey();
        if (empty ($hash_key)) {
            Mage::log("$this->_code: hash key misconfigured");
            Mage::throwException(Mage::helper('casmtp')->__('The "Hash authentication" configuration value is empty, please set this to the value assigned by Card Access Services'));
        }

        /* Check the proxy settings are ok */
        $proxy = $this->_createCasmtpProxy();

        return $this;
    }

    /**
     * Perform a capture of the transaction
     *
     * @param string  $payment           payment instance
     * @param float   $amount            amount to capture
     *
     * @return void
     * @access public
     */
    public function capture(Varien_Object $payment, $amount) {
        $cust_ref = CasMiscUtil::getCustRefFromPayment($payment);
        $this->_logPaymentEvent($payment, "capture invoked");
        $casmtp = $this->_createCasmtp();

        /* Get an audit number first */
        $audit = $this->_getAuditNumber($casmtp, $payment);

        /* Now do the actual purchase */
        try {
            $pan = $payment->getCcNumber();
            $cvv = $payment->getCcCid();
            $expiry = CasMiscUtil::formatExpiryFromPayment($payment);
            $this->_logPaymentEvent($payment, "starting capture for $audit (pan = xxxx-" . $payment->getCcLast4() . ", amount = $amount)");

            $result = $casmtp->purchase($audit, $pan, $expiry, $cvv, CasMiscUtil::flattenAmount($amount), $cust_ref);
        }
        catch (Exception $e) {
            /* This usually indicates some kind of wierd networking issue */
            Mage::log("$this->_code $cust_ref: error encountered: " . $e->getMessage());
            Mage::throwException(Mage::helper('casmtp')->__("There was an error encountered while performing the transaction"));
        }

        /* Interpret the transaction result */
        $this->_interpretTxnResult($result, $payment);

        return $this;
    }

    /**
     * Perform a refund of the transaction
     *
     * @param string  $payment           payment instance
     * @param float   $amount            amount to refund
     *
     * @return void
     * @access public
     */
    public function refund(Varien_Object $payment, $amount) {
        $cust_ref = CasMiscUtil::getCustRefFromPayment($payment);
        $this->_logPaymentEvent($payment, "refund invoked");

        /*
         * Filter out zero amounts just in case the care framework doesn't do this
         *
         * The gateway has no issue with this, but it's probably less confusing to the merchant if we block off
         * the transaction immediately
         */
        if (empty($amount)) {
            Mage::throwException(Mage::helper('casmtp')->__("Can't refund a zero amount"));
        }

        /* Make sure we have the audit number of the previous transaction */
        $old_audit = $payment->getLastTransId();
        if (empty($old_audit)) {
            Mage::throwException(Mage::helper('casmtp')->__("Previous transaction reference is empty - unable to locate previous transaction to refund"));
        }

        $casmtp = $this->_createCasmtp();

        /* Get a new audit number */
        $audit = $this->_getAuditNumber($casmtp, $payment);

        /* Do the refund */
        try {
            $this->_logPaymentEvent($payment, "starting refund for $audit (pan = xxxx-" . $payment->getCcLast4() . ", amount = $amount)");
            $result = $casmtp->refund($audit, $old_audit, CasMiscUtil::flattenAmount($amount));
        }
        catch (Exception $e) {
            // This usually indicates some kind of wierd networking issue
            $this->_logPaymentEvent($payment, "error encountered: " . $e->getMessage());
            Mage::throwException(Mage::helper('casmtp')->__("There was an error encountered while performing the transaction"));
        }

        /* Interpret the transaction result */
        $this->_interpretTxnResult($result, $payment);

        return $this;
    }
}
