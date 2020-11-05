from lib.functions import *
import posixpath
import csv


def attributes():
    """Output file attributes."""
    lexical = [
        'count_dot_url', 'count_hifen_url', 'count_underline_url',
        'count_bar_url', 'count_question_url', 'count_equal_url',
        'count_arroba_url', 'count_ampersand_url', 'count_exclamation_url',
        'count_blank_url', 'count_til_url', 'count_comma_url',
        'count_plus_url', 'count_asterisk_url', 'count_hashtag_url',
        'count_dollarsign_url', 'count_percentage_url', 'count_tld_url',
        'length_url', 'count_dot_host', 'count_hifen_host',
        'count_underline_host', 'count_bar_host', 'count_question_host',
        'count_equal_host', 'count_arroba_host', 'count_ampersand_host',
        'count_exclamation_host', 'count_blank_host', 'count_til_host',
        'count_comma_host', 'count_plus_host', 'count_asterik_host',
        'count_hashtag_host', 'count_dollarsign_host', 'count_percentage_host',
        'count_vowel_host', 'length_host', 'exist_ip_host',
        'server_client_host', 'count_dot_path', 'count_hifen_path',
        'count_underline_path', 'count_bar_path', 'count_question_path',
        'count_equal_path', 'count_arroba_path', 'count_ampersand_path',
        'count_exclamation_path', 'count_blank_path', 'count_til_path',
        'count_comma_path', 'count_plus_path', 'count_asterick_path',
        'count_hashtag_path', 'count_dollarsign_path', 'count_percentage_path',
        'length_path', 'count_dot_file', 'count_hifen_file',
        'count_underline_file', 'count_bar_file', 'count_question_file',
        'count_equal_file', 'count_arroba_file', 'count_ampersand_file',
        'count_exclamation_file', 'count_blank_file', 'count_til_file',
        'count_comma_file', 'count_plus_file', 'count_asterick_file',
        'count_hashtag_file', 'count_dollarsign_file', 'count_percentage_file',
        'length_file', 'count_dot_params', 'count_hifen_params',
        'count_underline_params', 'count_bar_params', 'count_question_params',
        'count_equal_params', 'count_arroba_params', 'count_ampersand_params',
        'count_exclamation_params', 'count_blank_params', 'count_til_params',
        'count_comma_params', 'count_plus_params', 'count_asterick_params',
        'count_hashtag_params', 'count_dollarsign_params', 'count_percentage_params',
        'length_params', 'present_tld_params', 'count_params',
        'present_email_url', 'extension_file',
        'ecommere_site','education_site','porn_site','entertainment_site',
        'bank_site','retail_site','lifestyle_site','tourism_site','sports_site',
        'payment_site','ftp_site','socialmedia_site','newsportal_site','fooddelivery_site',
        'ridesharing_site','moviedownload_site','site_google','game_site','apple_sites','torrent_sites',
        'defence_site','healthcare_site','authonication_site','music_site','gadgets_site',
        'fmtp_site','cgi_site','jsp_site','job_site','google_drive_site',
        'asp_site','image_site'
    ]

    blacklist = ['url_present_blacklists', 'ip_present_blacklists', 'domain_present_blacklists']

    host = ['domain_present_rbl', 'time_domain', 'spf', 'location_geographic_ip',
            'asn', 'ptr_ip', 'activation_domain_time', 'expiration_domain_time',
            'count_ip', 'count_nameservers', 'count_mx', 'valid_ttl_associate']

    others = ['certificate_tls_ssl', 'count_redirect', 'url_index_no_google', 'domain_index_no_google', 'url_shortener']

    list_attributes = []
    list_attributes.extend(lexical)
    list_attributes.extend(blacklist)
    list_attributes.extend(host)
    list_attributes.extend(others)
    list_attributes.extend(['phishing'])

    return list_attributes


def main(urls, dataset):
    with open(dataset, "w") as output:
        writer = csv.writer(output)
        writer.writerow(attributes())
        count_url = 0
        for url in read_file(urls):
            print(url)
            count_url = count_url + 1
            dict_url = start_url(url)

            """LEXICAL"""
            # URL
            dot_url = str(count(dict_url['url'], '.'))
            hyphe_url = str(count(dict_url['url'], '-'))
            underline_url = str(count(dict_url['url'], '_'))
            bar_url = str(count(dict_url['url'], '/'))
            question_url = str(count(dict_url['url'], '?'))
            equal_url = str(count(dict_url['url'], '='))
            arroba_url = str(count(dict_url['url'], '@'))
            ampersand_url = str(count(dict_url['url'], '&'))
            exclamation_url = str(count(dict_url['url'], '!'))
            blank_url = str(count(dict_url['url'], ' '))
            til_url = str(count(dict_url['url'], '~'))
            comma_url = str(count(dict_url['url'], ','))
            plus_url = str(count(dict_url['url'], '+'))
            asterisk_url = str(count(dict_url['url'], '*'))
            hashtag_url = str(count(dict_url['url'], '#'))
            money_sign_url = str(count(dict_url['url'], '$'))
            percentage_url = str(count(dict_url['url'], '%'))
            len_url = str(length(dict_url['url']))
            email_exist = str(valid_email(dict_url['url']))
            count_tld_url = str(count_tld(dict_url['url']))

            ###################

            ecommere_site = str(ecommerce(dict_url['url']))
            education_site = str(education(dict_url['url']))
            porn_site = str(porn(dict_url['url']))
            entertainment_site = str(entertainment(dict_url['url']))
            bank_site = str(bank(dict_url['url']))
            retail_site = str(retail(dict_url['url']))
            lifestyle_site = str(lifestyle(dict_url['url']))
            tourism_site = str(tourism(dict_url['url']))
            sports_site = str(sports(dict_url['url']))
            payment_site = str(payment(dict_url['url']))
            ftp_site = str(ftp(dict_url['url']))
            socialmedia_site = str(socialmedia(dict_url['url']))
            newsportal_site = str(newsportal(dict_url['url']))
            fooddelivery_site = str(fooddelivery(dict_url['url']))
            ridesharing_site = str(ridesharing(dict_url['url']))
            moviedownload_site = str(moviedownload(dict_url['url']))
            site_google = str(google_site(dict_url['url']))
            game_site = str(gaming_site(dict_url['url']))
            apple_sites = str(gaming_site(dict_url['url']))
            torrent_sites = str(torrent_site(dict_url['url']))
            defence_site = str(defence(dict_url['url']))
            healthcare_site = str(healthcare(dict_url['url']))
            authonication_site = str(authonication(dict_url['url']))
            music_site = str(music(dict_url['url']))
            gadgets_site = str(gadgets(dict_url['url']))
            fmtp_site = str(fmtp(dict_url['url']))
            cgi_site = str(cgi(dict_url['url']))
            jsp_site = str(jsp(dict_url['url']))
            job_site = str(job(dict_url['url']))
            google_drive_site = str(google_drive(dict_url['url']))
            asp_site = str(asp(dict_url['url']))
            image_site = str(image(dict_url['url']))



           




            # DOMAIN
            dot_host = str(count(dict_url['host'], '.'))
            hyphe_host = str(count(dict_url['host'], '-'))
            underline_host = str(count(dict_url['host'], '_'))
            bar_host = str(count(dict_url['host'], '/'))
            question_host = str(count(dict_url['host'], '?'))
            equal_host = str(count(dict_url['host'], '='))
            arroba_host = str(count(dict_url['host'], '@'))
            ampersand_host = str(count(dict_url['host'], '&'))
            exclamation_host = str(count(dict_url['host'], '!'))
            blank_host = str(count(dict_url['host'], ' '))
            til_host = str(count(dict_url['host'], '~'))
            comma_host = str(count(dict_url['host'], ','))
            plus_host = str(count(dict_url['host'], '+'))
            asterisk_host = str(count(dict_url['host'], '*'))
            hashtag_host = str(count(dict_url['host'], '#'))
            money_sign_host = str(count(dict_url['host'], '$'))
            percentage_host = str(count(dict_url['host'], '%'))
            vowels_host = str(count_vowels(dict_url['host']))
            len_host = str(length(dict_url['host']))
            ip_exist = str(valid_ip(dict_url['host']))
            server_client = str(check_word_server_client(dict_url['host']))
            # DIRECTORY
            if dict_url['path']:
                dot_path = str(count(dict_url['path'], '.'))
                hyphe_path = str(count(dict_url['path'], '-'))
                underline_path = str(count(dict_url['path'], '_'))
                bar_path = str(count(dict_url['path'], '/'))
                question_path = str(count(dict_url['path'], '?'))
                equal_path = str(count(dict_url['path'], '='))
                arroba_path = str(count(dict_url['path'], '@'))
                ampersand_path = str(count(dict_url['path'], '&'))
                exclamation_path = str(count(dict_url['path'], '!'))
                blank_path = str(count(dict_url['path'], ' '))
                til_path = str(count(dict_url['path'], '~'))
                comma_path = str(count(dict_url['path'], ','))
                plus_path = str(count(dict_url['path'], '+'))
                asterisk_path = str(count(dict_url['path'], '*'))
                hashtag_path = str(count(dict_url['path'], '#'))
                money_sign_path = str(count(dict_url['path'], '$'))
                percentage_path = str(count(dict_url['path'], '%'))
                len_path = str(length(dict_url['path']))
            else:
                dot_path = '?'
                hyphe_path = '?'
                underline_path = '?'
                bar_path = '?'
                question_path = '?'
                equal_path = '?'
                arroba_path = '?'
                ampersand_path = '?'
                exclamation_path = '?'
                blank_path = '?'
                til_path = '?'
                comma_path = '?'
                plus_path = '?'
                asterisk_path = '?'
                hashtag_path = '?'
                money_sign_path = '?'
                percentage_path = '?'
                len_path = '?'
            # FILE
            if dict_url['path']:
                dot_file = str(count(posixpath.basename(dict_url['path']), '.'))
                hyphe_file = str(count(posixpath.basename(dict_url['path']), '-'))
                underline_file = str(
                    count(posixpath.basename(dict_url['path']), '_'))
                bar_file = str(count(posixpath.basename(dict_url['path']), '/'))
                question_file = str(
                    count(posixpath.basename(dict_url['path']), '?'))
                equal_file = str(count(posixpath.basename(dict_url['path']), '='))
                arroba_file = str(count(posixpath.basename(dict_url['path']), '@'))
                ampersand_file = str(
                    count(posixpath.basename(dict_url['path']), '&'))
                exclamation_file = str(
                    count(posixpath.basename(dict_url['path']), '!'))
                blank_file = str(count(posixpath.basename(dict_url['path']), ' '))
                til_file = str(count(posixpath.basename(dict_url['path']), '~'))
                comma_file = str(count(posixpath.basename(dict_url['path']), ','))
                plus_file = str(count(posixpath.basename(dict_url['path']), '+'))
                asterisk_file = str(
                    count(posixpath.basename(dict_url['path']), '*'))
                hashtag_file = str(
                    count(posixpath.basename(dict_url['path']), '#'))
                money_sign_file = str(
                    count(posixpath.basename(dict_url['path']), '$'))
                percentage_file = str(
                    count(posixpath.basename(dict_url['path']), '%'))
                len_file = str(length(posixpath.basename(dict_url['path'])))
                extension = str(extract_extension(
                    posixpath.basename(dict_url['path'])))
            else:
                dot_file = '?'
                hyphe_file = '?'
                underline_file = '?'
                bar_file = '?'
                question_file = '?'
                equal_file = '?'
                arroba_file = '?'
                ampersand_file = '?'
                exclamation_file = '?'
                blank_file = '?'
                til_file = '?'
                comma_file = '?'
                plus_file = '?'
                asterisk_file = '?'
                hashtag_file = '?'
                money_sign_file = '?'
                percentage_file = '?'
                len_file = '?'
                extension = '?'
            # PARAMETERS
            if dict_url['query']:
                dot_params = str(count(dict_url['query'], '.'))
                hyphe_params = str(count(dict_url['query'], '-'))
                underline_params = str(count(dict_url['query'], '_'))
                bar_params = str(count(dict_url['query'], '/'))
                question_params = str(count(dict_url['query'], '?'))
                equal_params = str(count(dict_url['query'], '='))
                arroba_params = str(count(dict_url['query'], '@'))
                ampersand_params = str(count(dict_url['query'], '&'))
                exclamation_params = str(count(dict_url['query'], '!'))
                blank_params = str(count(dict_url['query'], ' '))
                til_params = str(count(dict_url['query'], '~'))
                comma_params = str(count(dict_url['query'], ','))
                plus_params = str(count(dict_url['query'], '+'))
                asterisk_params = str(count(dict_url['query'], '*'))
                hashtag_params = str(count(dict_url['query'], '#'))
                money_sign_params = str(count(dict_url['query'], '$'))
                percentage_params = str(count(dict_url['query'], '%'))
                len_params = str(length(dict_url['query']))
                tld_params = str(check_tld(dict_url['query']))
                number_params = str(count_params(dict_url['query']))
            else:
                dot_params = '?'
                hyphe_params = '?'
                underline_params = '?'
                bar_params = '?'
                question_params = '?'
                equal_params = '?'
                arroba_params = '?'
                ampersand_params = '?'
                exclamation_params = '?'
                blank_params = '?'
                til_params = '?'
                comma_params = '?'
                plus_params = '?'
                asterisk_params = '?'
                hashtag_params = '?'
                money_sign_params = '?'
                percentage_params = '?'
                len_params = '?'
                tld_params = '?'
                number_params = '?'

            """BLACKLIST"""
            blacklist_url = str(check_blacklists(dict_url['protocol'] + '://' + dict_url['url']))
            blacklist_ip = str(check_blacklists_ip(dict_url))
            blacklist_domain = str(check_blacklists(dict_url['protocol'] + '://' + dict_url['host']))

            """HOST"""
            spf = str(valid_spf(dict_url['host']))
            rbl = str(check_rbl(dict_url['host']))
            time_domain = str(check_time_response(dict_url['protocol'] + '://' + dict_url['host']))
            asn = str(get_asn_number(dict_url))
            country = str(get_country(dict_url))
            ptr = str(get_ptr(dict_url))
            activation_time = str(time_activation_domain(dict_url))
            expiration_time = str(expiration_date_register(dict_url))
            count_ip = str(count_ips(dict_url))
            count_ns = str(count_name_servers(dict_url))
            count_mx = str(count_mx_servers(dict_url))
            ttl = str(extract_ttl(dict_url))

            """OTHERS"""
            ssl = str(check_ssl('https://' + dict_url['url']))
            count_redirect = str(count_redirects(dict_url['protocol'] + '://' + dict_url['url']))
            google_url = str(google_search(dict_url['url']))
            google_domain = str(google_search(dict_url['host']))
            shortener = str(check_shortener(dict_url))

            _lexical = [
                dot_url, hyphe_url, underline_url, bar_url, question_url,
                equal_url, arroba_url, ampersand_url, exclamation_url,
                blank_url, til_url, comma_url, plus_url, asterisk_url, hashtag_url,
                money_sign_url, percentage_url, count_tld_url, len_url, dot_host,
                hyphe_host, underline_host, bar_host, question_host, equal_host,
                arroba_host, ampersand_host, exclamation_host, blank_host, til_host,
                comma_host, plus_host, asterisk_host, hashtag_host, money_sign_host,
                percentage_host, vowels_host, len_host, ip_exist, server_client,
                dot_path, hyphe_path, underline_path, bar_path, question_path,
                equal_path, arroba_path, ampersand_path, exclamation_path,
                blank_path, til_path, comma_path, plus_path, asterisk_path,
                hashtag_path, money_sign_path, percentage_path, len_path, dot_file,
                hyphe_file, underline_file, bar_file, question_file, equal_file,
                arroba_file, ampersand_file, exclamation_file, blank_file,
                til_file, comma_file, plus_file, asterisk_file, hashtag_file,
                money_sign_file, percentage_file, len_file, dot_params,
                hyphe_params, underline_params, bar_params, question_params,
                equal_params, arroba_params, ampersand_params, exclamation_params,
                blank_params, til_params, comma_params, plus_params, asterisk_params,
                hashtag_params, money_sign_params, percentage_params, len_params,
                tld_params, number_params, email_exist, extension,ecommere_site,education_site,
                porn_site,entertainment_site,bank_site,retail_site,lifestyle_site,tourism_site,
                sports_site,payment_site,ftp_site,socialmedia_site,newsportal_site,fooddelivery_site,
                ridesharing_site,moviedownload_site,site_google,game_site,apple_sites,torrent_sites,
                defence_site,healthcare_site,authonication_site,music_site,gadgets_site,fmtp_site,cgi_site,
                jsp_site,job_site,google_drive_site,asp_site,image_site
            ]


            _blacklist = [blacklist_url, blacklist_ip, blacklist_domain]

            _host = [rbl, time_domain, spf, country, asn, ptr, activation_time,
                     expiration_time, count_ip, count_ns, count_mx, ttl]

            _others = [ssl, count_redirect, google_url, google_domain, shortener]

            result = []
            result.extend(_lexical)
            result.extend(_blacklist)
            result.extend(_host)
            result.extend(_others)
            result.extend([''])

            writer.writerow(result)
