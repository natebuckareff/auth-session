import { NextPage, NextPageContext } from 'next';
import Head from 'next/head';
import React from 'react';
import { AntiCSRF, AntiCSRFContext } from './AntiCSRF';

export class NextAntiCSRF extends AntiCSRF {
    hoc<P>(Component: NextPage<P>): NextPage<P & { csrfToken: string }> {
        type Props = P & { csrfToken: string };

        const csrfToken = this.create();

        return class WithAntiCSRF extends React.Component<Props> {
            static async getInitialProps(context: NextPageContext) {
                if (Component.getInitialProps) {
                    return {
                        csrfToken,
                        ...(await Component.getInitialProps(context)),
                    };
                } else {
                    return { csrfToken };
                }
            }

            render() {
                const { csrfToken, ...props } = this.props;
                return (
                    <AntiCSRFContext.Provider value={csrfToken}>
                        <Head>
                            <meta
                                key={`csrf-token-${csrfToken}`}
                                name="csrf-token"
                                content={csrfToken}
                            />
                        </Head>
                        <Component {...(props as P)} />
                    </AntiCSRFContext.Provider>
                );
            }
        } as NextPage<Props>;
    }
}
