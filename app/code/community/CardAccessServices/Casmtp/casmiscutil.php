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
 * Utility class
 *
 * Most of the methods are highly specific to this particular shopping cart
 */
class CasMiscUtil {
    /**
     * Flatten the supplied amount
     *
     * @param string  $amt               amount to flatten
     *
     * @return string  the flattened amount
     * @access public
     */
    public static function flattenAmount($amt) {
        return number_format($amt, 2, '', '');
    }

    /**
     * Format the expiry date from a payment object
     *
     * @param string  $payment           payment instance
     *
     * @return string  the formatted expiry date
     * @access public
     */
    public static function formatExpiryFromPayment(&$payment) {
        return sprintf("%02d%02d", $payment->getCcExpYear() % 100, $payment->getCcExpMonth());
    }

    /**
     * Get a suitable transaction reference from a payment object
     *
     * @param string  $payment           payment instance
     *
     * @return string  the transaction reference
     * @access private
     */
    public static function getCustRefFromPayment($payment) {
        return $payment->getOrder()->getIncrementId();
    }

    /**
     * Retrieve the value for a given key, throwing an exception if it doesn't exist
     *
     * @param string  $reply             the response array
     * @param string  $name              the name of the expected key
     * @param string  $errmsg            the error message to include in the exception if the key doesn't exist
     *
     * @return string  the formatted expiry date
     * @access public
     */
    public static function getRequiredValue(&$reply, $name, $errmsg) {
        if (isset($reply[$name])) {
            return $reply[$name];
        }
        else {
            throw new Exception($errmsg);
        }
    }
}
