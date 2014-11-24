/*
* CVC EAC1.1 tests
*
* (C) 2008 Falko Strenzke (strenzke@flexsecure.de)
*      2008 Jack Lloyd
*/
module botan.cert.cvc.test;

import botan.constants;
static if(BOTAN_TEST && BOTAN_HAS_CARD_VERIFIABLE_CERTIFICATES):

import botan.test;
import botan.rng.auto_rng;
import botan.pubkey.algo.ecdsa;
import botan.pubkey.algo.rsa;

import botan.cert.x509.x509cert;
import botan.cert.x509.x509self;
import botan.asn1.oids;
import botan.cert.cvc.cvc_self;
import botan.cert.cvc.cvc_ado;
import botan.cert.cvc.cvc_cert;
import botan.utils.types;
import botan.utils.memory.memory;

// helper functions
void helper_write_file(in EAC_Signed_Object to_write, in string file_path)
{
    Vector!ubyte sv = to_write.BER_encode();
    File cert_file = File(file_path, "wb+");
    cert_file.write(sv.ptr[0 .. sv.length]);
}

bool helper_files_equal(in string file_path1, in string file_path2)
{
    File cert_1_in = File(file_path1, "r");
    File cert_2_in = File(file_path2, "r");
    Vector!ubyte sv1;
    Vector!ubyte sv2;
    if (!cert_1_in || !cert_2_in)
    {
        return false;
    }
    while (!cert_1_in.eof && !cert_1_in.error)
    {
        ubyte[16] now;
        auto data = cert_1_in.read(now.ptr[0 .. now.length]);
        sv1.push_back(data);
    }
    while (!cert_2_in.eof && !cert_2_in.error)
    {
        ubyte[16] now;
        auto data = cert_2_in.read(now.ptr[0 .. now.length]);
        sv2.push_back(data);
    }
    if (sv1.length == 0)
    {
        return false;
    }
    return sv1 == sv2;
}

void test_enc_gen_selfsigned(RandomNumberGenerator rng)
{
    EAC1_1_CVC_Options opts;
    //opts.cpi = 0;
    opts.chr = ASN1_Chr("my_opt_chr"); // not used
    opts.car = ASN1_Car("my_opt_car");
    opts.cex = ASN1_Cex("2010 08 13");
    opts.ced = ASN1_Ced("2010 07 27");
    opts.holder_auth_templ = 0xC1;
    opts.hash_alg = "SHA-256";
    
    // creating a non sense selfsigned cert w/o dom pars
    EC_Group dom_pars = EC_Group(OID("1.3.36.3.3.2.8.1.1.11"));
    auto key = scoped!ECDSA_PrivateKey(rng, dom_pars);
    key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
    EAC1_1_CVC cert = create_self_signed_cert(key, opts, rng);
    {
        Vector!ubyte der = cert.BER_encode();
        File cert_file = File("test_data/ecc/my_cv_cert.ber", "wb+");
        //cert_file << der; // this is bad !!!
        cert_file.write(cast(string) der.ptr[0 .. der.length]);
    }
    
    EAC1_1_CVC cert_in = EAC1_1_CVC("test_data/ecc/my_cv_cert.ber");
    mixin( CHECK(` cert == cert_in `) );
    // encoding it again while it has no dp
    {
        Vector!ubyte der2 = cert_in.BER_encode();
        File cert_file2 = File("test_data/ecc/my_cv_cert2.ber", "wb+");
        cert_file2.write(der2.ptr[0 .. der2.length]);
    }
    // read both and compare them
    {
        File cert_1_in = File("test_data/ecc/my_cv_cert.ber", "r");
        File cert_2_in = File("test_data/ecc/my_cv_cert2.ber", "r");
        Vector!ubyte sv1;
        Vector!ubyte sv2;
        if (!cert_1_in || !cert_2_in)
        {
            mixin( CHECK_MESSAGE( false, "could not read certificate files" ) );
        }
        while (!cert_1_in.eof && !cert_1_in.error)
        {
            ubyte[16] now;
            auto data = cert_1_in.read(now.ptr[0 .. now.length]);
            sv1.push_back(data);
        }
        while (!cert_2_in.eof && !cert_2_in.error)
        {
            ubyte[16] now;
            auto data = cert_2_in.read(now.ptr[0 .. now.length]);
            sv2.push_back(data);
        }
        mixin( CHECK(` sv1.length > 10 `) );
        mixin( CHECK_MESSAGE( sv1 == sv2, "reencoded file of cert without domain parameters is different from original" ) );
    }
    //cout " ~reading cert again");
    mixin( CHECK(` cert_in.get_car().value() == "my_opt_car" `) );
    mixin( CHECK(` cert_in.get_chr().value() == "my_opt_car" `) );
    mixin( CHECK(` cert_in.get_ced().as_string() == "20100727" `) );
    mixin( CHECK(` cert_in.get_ced().readable_string() == "2010/07/27 " `) );
    
    bool ill_date_exc = false;
    try
    {
        ASN1_Ced("1999 01 01");
    }
    catch
    {
        ill_date_exc = true;
    }
    mixin( CHECK(` ill_date_exc `) );
    
    bool ill_date_exc2 = false;
    try
    {
        ASN1_Ced("2100 01 01");
    }
    catch
    {
        ill_date_exc2 = true;
    }
    mixin( CHECK(` ill_date_exc2 `) );
    //cout " ~readable = '" ~ cert_in.get_ced().readable_string() " ~'");
    Unique!Public_Key p_pk = cert_in.subject_public_key();
    ECDSA_PublicKey p_ecdsa_pk = cast(ECDSA_PublicKey)(*p_pk);
    
    // let´s see if encoding is truely implicitca, because this is what the key should have
    // been set to when decoding (see above)(because it has no domain params):
    
    mixin( CHECK(` p_ecdsa_pk.domain_format() == EC_DOMPAR_ENC_IMPLICITCA `) );
    bool exc = false;
    try
    {
        writeln("order = " ~ p_ecdsa_pk.domain().get_order());
    }
    catch (Invalid_State)
    {
        exc = true;
    }
    mixin( CHECK(` exc `) );
    // set them and try again
    //cert_in -> set_domain_parameters(dom_pars);
    Unique!Public_Key p_pk2 = cert_in.subject_public_key();
    ECDSA_PublicKey p_ecdsa_pk2 = cast(ECDSA_PublicKey)(*p_pk2);
    //p_ecdsa_pk2 -> set_domain_parameters(dom_pars);
    mixin( CHECK(` p_ecdsa_pk2.domain().get_order() == dom_pars.get_order() `) );
    bool ver_ec = cert_in.check_signature(*p_pk2);
    mixin( CHECK_MESSAGE( ver_ec, "could not positively verify correct selfsigned cvc certificate" ) );
}

void test_enc_gen_req(RandomNumberGenerator rng)
{
    EAC1_1_CVC_Options opts;
    
    //opts.cpi = 0;
    opts.chr = ASN1_Chr("my_opt_chr");
    opts.hash_alg = "SHA-160";
    
    // creating a non sense selfsigned cert w/o dom pars
    EC_Group dom_pars = EC_Group(OID("1.3.132.0.8"));
    auto key = scoped!ECDSA_PrivateKey(rng, dom_pars);
    key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
    EAC1_1_Req req = create_cvc_req(key, opts.chr, opts.hash_alg, rng);
    {
        Vector!ubyte der = req.BER_encode();
        File req_file = File("test_data/ecc/my_cv_req.ber", "wb+");
        req_file.write(der.ptr[0 .. der.length]);
    }
    
    // read and check signature...
    EAC1_1_Req req_in = EAC1_1_Req("test_data/ecc/my_cv_req.ber");
    //req_in.set_domain_parameters(dom_pars);
    Unique!Public_Key p_pk = req_in.subject_public_key();
    ECDSA_PublicKey p_ecdsa_pk = cast(ECDSA_PublicKey)(*p_pk);
    //p_ecdsa_pk.set_domain_parameters(dom_pars);
    mixin( CHECK(` p_ecdsa_pk.domain().get_order() == dom_pars.get_order() `) );
    bool ver_ec = req_in.check_signature(*p_pk);
    mixin( CHECK_MESSAGE( ver_ec, "could not positively verify correct selfsigned (created by myself) cvc request" ) );
}

void test_cvc_req_ext(RandomNumberGenerator)
{
    EAC1_1_Req req_in = EAC1_1_Req("test_data/ecc/DE1_flen_chars_cvcRequest_ECDSA.der");
    EC_Group dom_pars = EC_Group(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
    //req_in.set_domain_parameters(dom_pars);
    Unique!Public_Key p_pk = req_in.subject_public_key();
    ECDSA_PublicKey p_ecdsa_pk = cast(ECDSA_PublicKey)(*p_pk);
    //p_ecdsa_pk.set_domain_parameters(dom_pars);
    mixin( CHECK(` p_ecdsa_pk.domain().get_order() == dom_pars.get_order() `) );
    bool ver_ec = req_in.check_signature(*p_pk);
    mixin( CHECK_MESSAGE( ver_ec, "could not positively verify correct selfsigned (external testdata) cvc request" ) );
}

void test_cvc_ado_ext(RandomNumberGenerator)
{
    EAC1_1_ADO req_in = EAC1_1_ADO("test_data/ecc/ado.cvcreq");
    EC_Group dom_pars = EC_Group(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
    //cout " ~car = " ~ req_in.get_car().value());
    //req_in.set_domain_parameters(dom_pars);
}

void test_cvc_ado_creation(RandomNumberGenerator rng)
{
    EAC1_1_CVC_Options opts;
    //opts.cpi = 0;
    opts.chr = ASN1_Chr("my_opt_chr");
    opts.hash_alg = "SHA-256";
    
    // creating a non sense selfsigned cert w/o dom pars
    EC_Group dom_pars = EC_Group(OID("1.3.36.3.3.2.8.1.1.11"));
    //cout " ~mod = " ~ hex << dom_pars.get_curve().get_p());
    auto req_key = scoped!ECDSA_PrivateKey(rng, dom_pars);
    req_key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
    //EAC1_1_Req req = create_cvc_req(req_key, opts);
    EAC1_1_Req req = create_cvc_req(req_key, opts.chr, opts.hash_alg, rng);
    {
        Vector!ubyte der = req.BER_encode();
        File req_file = File("test_data/ecc/my_cv_req.ber", "wb+");
        req_file.write(der.ptr[0 .. der.length]);
    }
    
    // create an ado with that req
    auto ado_key = scoped!ECDSA_PrivateKey(rng, dom_pars);
    EAC1_1_CVC_Options ado_opts;
    ado_opts.car = ASN1_Car("my_ado_car");
    ado_opts.hash_alg = "SHA-256"; // must be equal to req´s hash alg, because ado takes his sig_algo from it´s request
    
    //EAC1_1_ADO ado = create_ado_req(ado_key, req, ado_opts);
    EAC1_1_ADO ado = create_ado_req(ado_key, req, ado_opts.car, rng);
    mixin( CHECK_MESSAGE( ado.check_signature(ado_key), "failure of ado verification after creation" ) );
    
    {
        File ado_file = File("test_data/ecc/ado", "wb+");
        Vector!ubyte ado_der = ado.BER_encode();
        ado_file.write(ado_der.ptr[0 .. ado_der.length]);
    }
    // read it again and check the signature
    EAC1_1_ADO ado2 = EAC1_1_ADO("test_data/ecc/ado");
    mixin( CHECK(` ado == ado2 `) );
    //ECDSA_PublicKey p_ado_pk = cast(ECDSA_PublicKey)(&ado_key);
    //bool ver = ado2.check_signature(*p_ado_pk);
    bool ver = ado2.check_signature(ado_key);
    mixin( CHECK_MESSAGE( ver, "failure of ado verification after reloading" ) );
}

void test_cvc_ado_comparison(RandomNumberGenerator rng)
{
    EAC1_1_CVC_Options opts;
    //opts.cpi = 0;
    opts.chr = ASN1_Chr("my_opt_chr");
    opts.hash_alg = "SHA-224";
    
    // creating a non sense selfsigned cert w/o dom pars
    EC_Group dom_pars = EC_Group(OID("1.3.36.3.3.2.8.1.1.11"));
    auto req_key = scoped!ECDSA_PrivateKey(rng, dom_pars);
    req_key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
    //EAC1_1_Req req = create_cvc_req(req_key, opts);
    EAC1_1_Req req = create_cvc_req(req_key, opts.chr, opts.hash_alg, rng);
    
    // create an ado with that req
    auto ado_key = scoped!ECDSA_PrivateKey(rng, dom_pars);
    EAC1_1_CVC_Options ado_opts;
    ado_opts.car = ASN1_Car("my_ado_car1");
    ado_opts.hash_alg = "SHA-224"; // must be equal to req's hash alg, because ado takes his sig_algo from it's request
    //EAC1_1_ADO ado = create_ado_req(ado_key, req, ado_opts);
    EAC1_1_ADO ado = create_ado_req(ado_key, req, ado_opts.car, rng);
    mixin( CHECK_MESSAGE( ado.check_signature(ado_key), "failure of ado verification after creation" ) );
    // make a second one for comparison
    EAC1_1_CVC_Options opts2;
    //opts2.cpi = 0;
    opts2.chr = ASN1_Chr("my_opt_chr");
    opts2.hash_alg = "SHA-160"; // this is the only difference
    auto req_key2 = scoped!ECDSA_PrivateKey(rng, dom_pars);
    req_key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
    //EAC1_1_Req req2 = create_cvc_req(req_key2, opts2, rng);
    EAC1_1_Req req2 = create_cvc_req(req_key2, opts2.chr, opts2.hash_alg, rng);
    auto ado_key2 = scoped!ECDSA_PrivateKey(rng, dom_pars);
    EAC1_1_CVC_Options ado_opts2;
    ado_opts2.car = ASN1_Car("my_ado_car1");
    ado_opts2.hash_alg = "SHA-160"; // must be equal to req's hash alg, because ado takes his sig_algo from it's request
    
    EAC1_1_ADO ado2 = create_ado_req(ado_key2, req2, ado_opts2.car, rng);
    mixin( CHECK_MESSAGE( ado2.check_signature(ado_key2), "failure of ado verification after creation" ) );
    
    mixin( CHECK_MESSAGE( ado != ado2, "ado's found to be equal where they are not" ) );
    //      std::ofstream ado_file("test_data/ecc/ado");
    //      Vector!ubyte ado_der(ado.BER_encode());
    //      ado_file.write((char*)&ado_der[0], ado_der.length);
    //      ado_file.close();
    // read it again and check the signature
    
    //     EAC1_1_ADO ado2("test_data/ecc/ado");
    //     ECDSA_PublicKey p_ado_pk = cast(ECDSA_PublicKey)(&ado_key);
    //     //bool ver = ado2.check_signature(p_ado_pk);
    //     bool ver = ado2.check_signature(ado_key);
    //     mixin( CHECK_MESSAGE( ver, "failure of ado verification after reloading" ) );
}

void test_eac_time(RandomNumberGenerator)
{
    EAC_Time time = EAC_Time(Clock.currTime(UTC()));
    //      writeln("time as string = " ~ time.as_string());
    EAC_Time sooner = EAC_Time("", ASN1_Tag(99));
    //X509_Time sooner("", ASN1_Tag(99));
    sooner.set_to("2007 12 12");
    //      writeln("sooner as string = " ~ sooner.as_string());
    EAC_Time later = EAC_Time("2007 12 13");
    //X509_Time later("2007 12 13");
    //      writeln("later as string = " ~ later.as_string());
    mixin( CHECK(` sooner <= later `) );
    mixin( CHECK(` sooner == sooner `) );
    
    ASN1_Cex my_cex = ASN1_Cex("2007 08 01");
    my_cex.add_months(12);
    mixin( CHECK(` my_cex.get_year() == 2008 `) );
    mixin( CHECK_MESSAGE( my_cex.get_month() == 8, "shoult be 8, was " ~ my_cex.get_month() ) );
    
    my_cex.add_months(4);
    mixin( CHECK(` my_cex.get_year() == 2008 `) );
    mixin( CHECK(` my_cex.get_month() == 12 `) );
    
    my_cex.add_months(4);
    mixin( CHECK(` my_cex.get_year() == 2009 `) );
    mixin( CHECK(` my_cex.get_month() == 4 `) );
    
    my_cex.add_months(41);
    mixin( CHECK(` my_cex.get_year() == 2012 `) );
    mixin( CHECK(` my_cex.get_month() == 9 `) );
    
    
    
}

void test_ver_cvca(RandomNumberGenerator)
{
    EAC1_1_CVC req_in = EAC1_1_CVC("test_data/ecc/cvca01.cv.crt");
    
    bool exc = false;
    
    Unique!Public_Key p_pk2 = req_in.subject_public_key();
    ECDSA_PublicKey p_ecdsa_pk2 = cast(ECDSA_PublicKey)(*p_pk2);
    bool ver_ec = req_in.check_signature(*p_pk2);
    mixin( CHECK_MESSAGE( ver_ec, "could not positively verify correct selfsigned cvca certificate" ) );
    
    try
    {
        p_ecdsa_pk2.domain().get_order();
    }
    catch (Invalid_State)
    {
        exc = true;
    }
    mixin( CHECK(` !exc `) );
}

void test_copy_and_assignment(RandomNumberGenerator)
{
    EAC1_1_CVC cert_in = EAC1_1_CVC("test_data/ecc/cvca01.cv.crt");
    EAC1_1_CVC cert_cp = EAC1_1_CVC(cert_in);
    EAC1_1_CVC cert_ass = cert_in;
    mixin( CHECK(` cert_in == cert_cp `) );
    mixin( CHECK(` cert_in == cert_ass `) );
    
    EAC1_1_ADO ado_in = EAC1_1_ADO("test_data/ecc/ado.cvcreq");
    //EC_Group dom_pars = EC_Group(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
    EAC1_1_ADO ado_cp = EAC1_1_ADO(ado_in);
    EAC1_1_ADO ado_ass = ado_in;
    mixin( CHECK(` ado_in == ado_cp `) );
    mixin( CHECK(` ado_in == ado_ass `) );
    
    EAC1_1_Req req_in = EAC1_1_Req("test_data/ecc/DE1_flen_chars_cvcRequest_ECDSA.der");
    //EC_Group dom_pars = EC_Group(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
    EAC1_1_Req req_cp = EAC1_1_Req(req_in);
    EAC1_1_Req req_ass = req_in;
    mixin( CHECK(` req_in == req_cp `) );
    mixin( CHECK(` req_in == req_ass `) );
}

void test_eac_str_illegal_values(RandomNumberGenerator)
{
    bool exc = false;
    try
    {
        EAC1_1_CVC("test_data/ecc/cvca_illegal_chars.cv.crt");
        
    }
    catch (Decoding_Error)
    {
        exc = true;
    }
    mixin( CHECK(` exc `) );
    
    bool exc2 = false;
    try
    {
        EAC1_1_CVC("test_data/ecc/cvca_illegal_chars2.cv.crt");
        
    }
    catch (Decoding_Error)
    {
        exc2 = true;
    }
    mixin( CHECK(` exc2 `) );
}

void test_tmp_eac_str_enc(RandomNumberGenerator)
{
    bool exc = false;
    try
    {
        ASN1_Car("abc!+-µ\n");
    }
    catch (Invalid_Argument)
    {
        exc = true;
    }
    mixin( CHECK(` exc `) );
    //      string val = car.iso_8859();
    //      writeln("car 8859 = " ~ val);
    //      writeln(hex <<(unsigned char)val[1]);
}

void test_cvc_chain(RandomNumberGenerator rng)
{
    EC_Group dom_pars = EC_Group(OID("1.3.36.3.3.2.8.1.1.5")); // "german curve"
    auto cvca_privk = scoped!ECDSA_PrivateKey(rng, dom_pars);
    string hash = "SHA-224";
    ASN1_Car car = ASN1_Car("DECVCA00001");
    EAC1_1_CVC cvca_cert = cvc_self.create_cvca(cvca_privk, hash, car, true, true, 12, rng);
    {
        File cvca_file = File("test_data/ecc/cvc_chain_cvca.cer","wb+");
        Vector!ubyte cvca_sv = cvca_cert.BER_encode();
        cvca_file.write(cast(string) cvca_sv.ptr[0 .. cvca_sv.length]);
    }
    
    auto cvca_privk2 = scoped!ECDSA_PrivateKey(rng, dom_pars);
    ASN1_Car car2 = ASN1_Car("DECVCA00002");
    EAC1_1_CVC cvca_cert2 = cvc_self.create_cvca(cvca_privk2, hash, car2, true, true, 12, rng);
    EAC1_1_CVC link12 = cvc_self.link_cvca(cvca_cert, cvca_privk, cvca_cert2, rng);
    {
        Vector!ubyte link12_sv = link12.BER_encode();
        File link12_file = File("test_data/ecc/cvc_chain_link12.cer", "wb+");
        link12_file.write(link12_sv.ptr[0 .. link12_sv.length]);
    }
    
    // verify the link
    mixin( CHECK(` link12.check_signature(cvca_privk) `) );
    EAC1_1_CVC link12_reloaded = EAC1_1_CVC("test_data/ecc/cvc_chain_link12.cer");
    EAC1_1_CVC cvca1_reloaded = EAC1_1_CVC("test_data/ecc/cvc_chain_cvca.cer");
    Unique!Public_Key cvca1_rel_pk = cvca1_reloaded.subject_public_key();
    mixin( CHECK(` link12_reloaded.check_signature(*cvca1_rel_pk) `) );
    
    // create first round dvca-req
    auto dvca_priv_key = scoped!ECDSA_PrivateKey(rng, dom_pars);
    EAC1_1_Req dvca_req = cvc_self.create_cvc_req(dvca_priv_key, ASN1_Chr("DEDVCAEPASS"), hash, rng);
    {
        File dvca_file = File("test_data/ecc/cvc_chain_dvca_req.cer", "wb+");
        Vector!ubyte dvca_sv = dvca_req.BER_encode();
        dvca_file.write(dvca_sv.ptr[0 .. dvca_sv.length]);
    }
    
    // sign the dvca_request
    EAC1_1_CVC dvca_cert1 = cvc_self.sign_request(cvca_cert, cvca_privk, dvca_req, 1, 5, true, 3, 1, rng);
    mixin( CHECK(` dvca_cert1.get_car().iso_8859() == "DECVCA00001" `) );
    mixin( CHECK(` dvca_cert1.get_chr().iso_8859() == "DEDVCAEPASS00001" `) );
    helper_write_file(dvca_cert1, "test_data/ecc/cvc_chain_dvca_cert1.cer");
    
    // make a second round dvca ado request
    auto dvca_priv_key2 = scoped!ECDSA_PrivateKey(rng, dom_pars);
    EAC1_1_Req dvca_req2 = cvc_self.create_cvc_req(dvca_priv_key2, ASN1_Chr("DEDVCAEPASS"), hash, rng);
    {
        File dvca_file2 = File("test_data/ecc/cvc_chain_dvca_req2.cer", "wb+");
        Vector!ubyte dvca_sv2 = dvca_req2.BER_encode();
        dvca_file2.write(dvca_sv2.ptr[0 .. dvca_sv2.length]);
    }
    
    EAC1_1_ADO dvca_ado2 = create_ado_req(dvca_priv_key, dvca_req2, ASN1_Car(dvca_cert1.get_chr().iso_8859()), rng);
    helper_write_file(dvca_ado2, "test_data/ecc/cvc_chain_dvca_ado2.cer");
    
    // verify the ado and sign the request too
    
    Unique!Public_Key ap_pk = dvca_cert1.subject_public_key();
    ECDSA_PublicKey cert_pk = cast(ECDSA_PublicKey)(*ap_pk);
    
    //cert_pk.set_domain_parameters(dom_pars);
    //writeln("dvca_cert.public_point.length = " ~ ec::EC2OSP(cert_pk.get_public_point(), ec::PointGFp.COMPRESSED).length);
    EAC1_1_CVC dvca_cert1_reread = EAC1_1_CVC("test_data/ecc/cvc_chain_cvca.cer");
    mixin( CHECK(` dvca_ado2.check_signature(cert_pk) `) );
    
    mixin( CHECK(` dvca_ado2.check_signature(dvca_priv_key) `) ); // must also work
    
    EAC1_1_Req dvca_req2b = dvca_ado2.get_request();
    helper_write_file(dvca_req2b, "test_data/ecc/cvc_chain_dvca_req2b.cer");
    mixin( CHECK(` helper_files_equal("test_data/ecc/cvc_chain_dvca_req2b.cer", "test_data/ecc/cvc_chain_dvca_req2.cer") `) );
    EAC1_1_CVC dvca_cert2 = cvc_self.sign_request(cvca_cert, cvca_privk, dvca_req2b, 2, 5, true, 3, 1, rng);
    mixin( CHECK(` dvca_cert2.get_car().iso_8859() == "DECVCA00001" `) );
    CHECK_MESSAGE(dvca_cert2.get_chr().iso_8859() == "DEDVCAEPASS00002", "chr = " ~ dvca_cert2.get_chr().iso_8859());
    
    // make a first round IS request
    auto is_priv_key = scoped!ECDSA_PrivateKey(rng, dom_pars);
    EAC1_1_Req is_req = cvc_self.create_cvc_req(is_priv_key, ASN1_Chr("DEIS"), hash, rng);
    helper_write_file(is_req, "test_data/ecc/cvc_chain_is_req.cer");
    
    // sign the IS request
    //dvca_cert1.set_domain_parameters(dom_pars);
    EAC1_1_CVC is_cert1 = cvc_self.sign_request(dvca_cert1, dvca_priv_key, is_req, 1, 5, true, 3, 1, rng);
    mixin( CHECK_MESSAGE( is_cert1.get_car().iso_8859() == "DEDVCAEPASS00001", "car = " ~ is_cert1.get_car().iso_8859() ) );
    mixin( CHECK(` is_cert1.get_chr().iso_8859() == "DEIS00001" `) );
    helper_write_file(is_cert1, "test_data/ecc/cvc_chain_is_cert.cer");
    
    // verify the signature of the certificate
    mixin( CHECK(` is_cert1.check_signature(dvca_priv_key) `) );
}

unittest
{
    AutoSeeded_RNG rng;
    
    test_enc_gen_selfsigned(rng);
    test_enc_gen_req(rng);
    test_cvc_req_ext(rng);
    test_cvc_ado_ext(rng);
    test_cvc_ado_creation(rng);
    test_cvc_ado_comparison(rng);
    test_eac_time(rng);
    test_ver_cvca(rng);
    test_copy_and_assignment(rng);
    test_eac_str_illegal_values(rng);
    test_tmp_eac_str_enc(rng);
    test_cvc_chain(rng);

}