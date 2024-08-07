#!/usr/bin/python3

import os
import sys
import argparse
import datetime
import time
import traceback
from pathlib import Path
import uuid

import httpx
from requests import JSONDecodeError, ConnectionError, ConnectTimeout

from get_creds import get_creds

PRIVATE_KEY_FILENAME = "private.key"
CERTIFICATE_FILENAME = "private.pem"
SOURCE_PATH = Path(__file__).resolve().parent
FULL_KEY_FILE_PATH = os.path.join(SOURCE_PATH, PRIVATE_KEY_FILENAME)
FULL_CERT_FILE_PATH = os.path.join(SOURCE_PATH, CERTIFICATE_FILENAME)

categories_id_mapping = dict()

class Product:
    """
    Data-storage class for products.
    """

    def __init__(self):
        self._id = ''
        self._name = ''
        self._price = ''
        self._discount = ''
        self._discount_valid = ''
        self._base_price = ''
        self._description = ''
        self._category = ''
        self._currency = ''
        self.currency = '€'

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = self.__clean_string(name)

    @property
    def price(self):
        return self._price

    @price.setter
    def price(self, price):
        if price is str:
            self._price = self.__clean_string(price).replace('.', ',')
        else:
            self._price = str(price).replace('.', ',')

    @property
    def discount(self):
        return self._discount

    @discount.setter
    def discount(self, discount):
        self._discount = self.__clean_string(discount)

    @property
    def discount_valid(self):
        return self._discount_valid

    @discount_valid.setter
    def discount_valid(self, discount_valid):
        self._discount_valid = self.__clean_string(discount_valid)

    @property
    def base_price(self):
        return self._base_price

    @base_price.setter
    def base_price(self, base_price):
        self._base_price = self.__clean_string(base_price)

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, description):
        self._description = self.__clean_string(description)

    @property
    def category(self):
        return self._category

    @category.setter
    def category(self, category_id):
        if type(category_id) is int:
            self._category = self.__clean_string(categories_id_mapping[category_id])
        elif type(category_id) is str:
            self._category = self.__clean_string(category_id)

    @property
    def currency(self):
        return self._currency

    @currency.setter
    def currency(self, currency):
        self._currency = self.__clean_string(currency)

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, id):
        self._id = id

    def __clean_string(self, input):
        """
        Replaces all newline characters in an input string with blank spaces.

        Args:
            input (str): Input string.

        Returns:
            output (str): Cleaned output string.

        """
        output = (input.replace('\n', ' ').replace('\u2028', ' ')
                  .replace('\u000A', ' ').rstrip().lstrip())
        return output


def custom_exit(message):
    traceback.print_exc()
    print(message)
    sys.exit(1)

def print_market_ids(zip_code):
    # Craft query and load JSON stuff.
    
    files = os.listdir(SOURCE_PATH)
    if PRIVATE_KEY_FILENAME not in files or CERTIFICATE_FILENAME not in files:
        get_creds(source_path=SOURCE_PATH, key_filename=PRIVATE_KEY_FILENAME, cert_filename=CERTIFICATE_FILENAME)
    
    client_cert = FULL_CERT_FILE_PATH
    client_key = FULL_KEY_FILE_PATH
    hostname = "mobile-api.rewe.de"
    url = "https://" + hostname + "/api/v3/market/search?search=" + str(zip_code)
    rdfa_uuid = str(uuid.uuid4())
    correlation_id_uuid = str(uuid.uuid4())
    header = {
        "ruleVersion": "2",
        "user-agent": "REWE-Mobile-Client/3.17.1.32270 Android/11 Phone/Google_sdk_gphone_x86_64",
        "rdfa": rdfa_uuid,  #"d53d57e6-1f5a-4112-94aa-d900c1dc1556",
        "Correlation-Id": correlation_id_uuid,  #"c0147af1-8f04-49e8-b573-425c33b963b1",
        "rd-service-types": "UNKNOWN",
        "x-rd-service-types": "UNKNOWN",
        "rd-is-lsfk": "false",
        "rd-customer-zip": "",
        "rd-postcode": "",
        "x-rd-customer-zip": "",
        "rd-market-id": "",
        "x-rd-market-id": "",
        "a-b-test-groups": "productlist-citrusad",
        "Host": hostname,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
        }
    res = httpx.Client(http2=True, cert=(client_cert, client_key), headers=header).get(url)
    res = res.json()
    
    markets = res["markets"]

    if not markets:
        custom_exit('FAIL: No markets found near provided zip code "{}".'.format(zip_code))

    print('  ID     Location')
    for market in markets:
        print('{}: {}, {}, {} {}'.format(market['id'], market['name'], market['addressLine1'],
                                         market['rawValues']['postalCode'], market['rawValues']['city']))
    print('\nPlease choose the right market and its ID from above.\n\n'
          'Example program call to fetch all discounts from a market:\n'
          '  rewe_discounts.py --market-id ID --output-file "Angebote Rewe.md"')

    sys.exit(0)

def load_product_highlights():
    # Check and process highlights file
    product_highlights = []
    if highlight_file:
        try:
            with open(highlight_file, 'r') as file:
                all_lines = file.readlines()
            product_highlights = [item.strip('\n') for item in all_lines if
                                  not item.startswith('#') and item.strip('\n')]
        except FileNotFoundError:  # file not found or
            custom_exit('FAIL: Highlights file "{}" not found. '
                        'Please check for typos or create it and write one url per line.'.format(highlight_file))
        if not product_highlights:
            print('WARNING: No product highlights in file "{}" found. '
                  'Ignoring user request to highlight and continuing anyway.'.format(highlight_file))
    return product_highlights


def elegant_query(market_id):

    files = os.listdir(SOURCE_PATH)
    if PRIVATE_KEY_FILENAME not in files or CERTIFICATE_FILENAME not in files:
        get_creds(source_path=SOURCE_PATH, key_filename=PRIVATE_KEY_FILENAME, cert_filename=CERTIFICATE_FILENAME)
    
    client_cert = FULL_CERT_FILE_PATH
    client_key = FULL_KEY_FILE_PATH
    hostname = "mobile-clients-api.rewe.de"
    url = "https://" + hostname + "/api/stationary-app-offers/" + str(market_id)
    rdfa_uuid = str(uuid.uuid4())
    correlation_id_uuid = str(uuid.uuid4())
    header = {
        # "ruleVersion": "2",
        "user-agent": "REWE-Mobile-Client/3.17.1.32270 Android/11 Phone/Google_sdk_gphone_x86_64",
        "rdfa": rdfa_uuid,  #"d53d57e6-1f5a-4112-94aa-d900c1dc1556",
        "Correlation-Id": correlation_id_uuid,  #"c0147af1-8f04-49e8-b573-425c33b963b1",
        "rd-service-types": "UNKNOWN",
        "x-rd-service-types": "UNKNOWN",
        "rd-is-lsfk": "false",
        "rd-customer-zip": "",
        "rd-postcode": "",
        "x-rd-customer-zip": "",
        "rd-market-id": "",
        "x-rd-market-id": "",
        "a-b-test-groups": "productlist-citrusad",
        "Host": hostname,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        }
    res = httpx.Client(http2=True, cert=(client_cert, client_key), headers=header).get(url)
    res = res.json()
    data = res["data"]["offers"]

    # Reformat categories for easier access. ! are highlighted products, and ? are uncategorized ones.
    # Order of definition here determines printing order later on.
    categories = data['categories']
    categories_id_mapping.update({'!': 'Vorgemerkte Produkte'})
    categorized_products = {'!': []}
    for n in range(0, len(categories)):
        if 'PAYBACK' in categories[n]['title']:  # ignore payback offers
            continue
        categories_id_mapping.update({n: categories[n]['title']})
        categorized_products.update({n: []})
    categories_id_mapping.update({'?': 'Unbekannte Kategorie'})
    categorized_products.update({'?': []})

    # Get maximum valid date of offers
    offers_valid_date = time.strftime('%Y-%m-%d', time.localtime(data['untilDate'] / 1000))

    # Check and process highlights file
    product_highlights = load_product_highlights()

    # Stores product data in a dict with categories as keys for a sorted printing experience.
    # Sometimes the data from Rewe is mixed/missing, so that's why we need all those try/excepts.
    n = 0
    for category in data['categories']:
        if 'PAYBACK' in category['title']:  # ignore payback offers
            n += 1
            continue
        for item in category['offers']:
            # Some lines are for banners. Probably item['cellType'] == 'MOOD', but item['title'] == "" is safer.
            if item['title'] == "":
                continue
            NewProduct = Product()
            try:
                NewProduct.name = item['title']
                NewProduct.price = item['priceData']['price']
                NewProduct.base_price = item['subtitle']
            except KeyError:  # sometimes an item is blank or does not contain price information, skip it
                continue
            try:
                NewProduct.category = n
            except KeyError:  # if category not defined in _meta, assign to unknown category
                NewProduct.category = '?'

            # Move product into the respective category list ...
            try:
                categorized_products[n].append(NewProduct)
            except KeyError:
                categorized_products['?'].append(NewProduct)
            # ... but highlighted products are the only ones in two categories
            if any(x in NewProduct.name for x in product_highlights):
                categorized_products['!'].append(NewProduct)
        n += 1

    # Writes product list grouped by categories to file, and cleans file first
    with open(output_file, 'w') as file:
        file.truncate(0)
        for category_id in categorized_products:
            if category_id == '!':
                header = '# {}\nAlle Angebote gültig bis {}.\n\n'.format(categories_id_mapping[category_id],
                                                                         offers_valid_date)
            else:
                header = '# {}\n\n'.format(categories_id_mapping[category_id])
            file.write(header)
            for product in categorized_products[category_id]:
                file.write('**{}**\n'.format(product.name))
                file.write('- {}\n'.format(product.price))
                file.write("- {}\n".format(product.base_price))
                if product.discount_valid:
                    file.write("- {}\n".format(product.discount_valid))
                file.write('\n')
            file.write('\n')
        file.write("Update: {}".format(datetime.datetime.now()))

    if product_highlights:
        print('OK: Wrote {} discounts to file "{}" and highlighted {}.'.format(
            sum([len(categorized_products[x]) for x in categorized_products]) - len(categorized_products['!']),
            output_file,
            sum([len(categorized_products['!'])])))
    else:
        print('OK: Wrote {} discounts to file "{}".'.format(
            sum([len(categorized_products[x]) for x in categorized_products]), output_file))
    sys.exit(0)

if __name__ == '__main__':

    files = os.listdir(SOURCE_PATH)
    if PRIVATE_KEY_FILENAME not in files or CERTIFICATE_FILENAME not in files:
        get_creds(source_path=SOURCE_PATH, key_filename=PRIVATE_KEY_FILENAME, cert_filename=CERTIFICATE_FILENAME)

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Fetches current Rewe discount offers for a specific market.',
        epilog=
        'Example usages:\n'
        ' - Prints the market IDs of all Rewe markets in/near the zip code/PLZ "63773":\n'
        '      rewe_discounts.py --list-markets 63773\n'
        ' - Exports current discounts of the market with the ID "562286":\n'
        '      rewe_discounts.py --market-id 562286 --output-file "Angebote Rewe.md"\n'
        ' - Exports current discounts of the market with the ID "562286" and highlights defined products:\n'
        '      rewe_discounts.py --market-id 562286 --output-file "Angebote Rewe.md" --highlights=highlights.txt'
    )

    parser.add_argument('--market-id', type=str, help='Market ID, needs to be obtained by executing --list-markets.')
    parser.add_argument('--output-file', type=str, help='Output file path.')
    parser.add_argument('--highlights', type=str, help='Products mentioned in this file, e.g. "Joghurt", '
                                                       'are highlighted in the output file.')
    parser.add_argument('--list-markets', type=str, help='Given the zip code (PLZ), list all markets and their ID.')
    args = parser.parse_args()
    market_id = args.market_id
    output_file = args.output_file
    highlight_file = args.highlights

    # Here we differentiate between mode "print market IDs" and mode "print offers of selected market"
    if args.list_markets:  # mode "print market IDs"
        try:
            assert int(args.list_markets)
            assert len(args.list_markets) == 5
        except (ValueError, AssertionError):
            custom_exit(
                'FAIL: Unrecognized input "{}". Please provide a 5 digit postal code.'.format(args.list_markets))
        zip_code = args.list_markets
        print_market_ids(zip_code)

    else:  # mode "print offers of selected market"
        if not market_id or not output_file:
            parser.print_help()
            sys.exit(0)
        try:
            assert int(market_id)
            assert len(market_id) >= 6
            assert len(market_id) <= 7
        except (ValueError, AssertionError):
            custom_exit('FAIL: Unrecognized input "{}". Please provide a 6 or 7 digit market ID.'.format(args.market_id))

        # We have two methods of retrieving the data, the 'elegant' way by using only one API query, but which seems
        # rather unstable after some changes by REWE, and the 'less-elegant' way by using one API query for getting
        # all product ids, and then iterating over all product ids to get the related pricing information. The elegant
        # method is preferred, and fails to the less-elegant method.
        try:
            elegant_query(market_id)
        except (JSONDecodeError, ConnectionError, ConnectTimeout):
            print('INFO: Unknown error while fetching discounts.')
        except (KeyError, TypeError):  # data got retrieved successfully
            pass

