void search(){
	FILE *fptr;
	int ret;
	fptr = fopen("share_0.bin","rb");
	sss_share share;
	

	ret = fread(&share, 82, 1, fptr);
	ret = fclose(fptr);


	nn p;
	fp_ctx ctx;
	fp Pind;
	fp ind;
	fp try_inv;
	fp fp_output;
	fp s;
	fp exp;
	fp one;

	
	ret = nn_init_from_buf(&p,prime,0x20);
	ret = fp_ctx_init_from_p(&ctx,&p);
	ret = fp_init_from_buf(&Pind,&ctx,share.raw_share.share,32);
	ret = fp_init_from_buf(&ind,&ctx,share.raw_share.index,2);
	ret = fp_init(&try_inv,&ctx);
	ret = fp_init(&fp_output,&ctx);
	ret = fp_init(&s,&ctx);
	ret = fp_init(&one,&ctx);
	ret = fp_init(&exp,&ctx);


	
	
	
	

	// Simulate the mask with one
	
	ret = fp_one(&one);
	
	u8 secret[32];
	for (unsigned int random_value = (1<<16) - 1; random_value >0; --random_value){
		//start s at one, cause a[0] = secret_seed * 1
		ret = fp_one(&s);
		ret = fp_one(&exp);
		//On a fixé la random value et le N
		for(unsigned int N=1; N<70;++N){
			u8 i = N;
			u8 seed[4];
			*seed = (u8) random_value;
			*(seed+1) = (u8) (random_value>>8);
			*(seed+2) = 0;
			*(seed+3) = i;
			u8 hash_output[0x40];
			u8 len = 0x40;
			ret = hmac(seed,4,4,seed+2,2,hash_output,&len);
			nn nn_output;
			ret = nn_init_from_buf(&nn_output,hash_output,len);
			ret = nn_mod(&nn_output,&nn_output, &(ctx.p));
			
			ret = fp_set_nn(&fp_output,&nn_output);
			// exp = x^i
			ret = fp_mul_monty(&exp,&exp,&ind);

			// output = a[i]*x^i
			ret = fp_mul_monty(&fp_output,&fp_output,&one);

			ret = fp_mul_monty(&fp_output,&fp_output,&exp);

			// s = S(a[j]x^j) pour j<=i et a[0] = 1
			ret = fp_add(&s,&s,&fp_output);

			

			ret = fp_inv(&try_inv,&s);
			ret = fp_mul(&try_inv,&try_inv,&Pind);
			ret = fp_export_to_buf(secret,(u8)32,&try_inv);
			if(ret == -2){
				break;
			}
				
			

			u8 *cur_id = (u8*)&(share.session_id);
			u8 potential_hmac[32];
			/* NOTE: we 'abuse' casts here for shares[i].raw_share to u8*, but this should be OK since
			* our structures are packed.
			*/
			const u8 *inputs[3] = { (const u8*) &(share.raw_share), cur_id, NULL };
			const u32 ilens[3] = { sizeof(share.raw_share), SSS_SESSION_ID_SIZE, 0 };

			/* Copy the session ID */
			ret = local_memcpy(cur_id, share.session_id, SSS_SESSION_ID_SIZE); 

			u8 hmac_verif_len = SSS_HMAC_SIZE;
			ret = hmac_scattered((const u8*)secret, SSS_SECRET_SIZE, SHA256, inputs, ilens, potential_hmac, &hmac_verif_len);
		
			int cmp;
			ret = are_equal(share.raw_share_hmac, potential_hmac, hmac_verif_len, &cmp);
			if(cmp){
				printf("Found key");
				FILE* f = fopen("secret.bin","wb");
				fwrite(secret,32,1,f);
				fclose(f);
				break;
			}

			



		}
		printf("%d\n",random_value);
	}
}
