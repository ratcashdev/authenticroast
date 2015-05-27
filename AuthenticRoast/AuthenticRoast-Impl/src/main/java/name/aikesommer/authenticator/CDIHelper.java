/**
 *    Copyright (C) 2015 OmniSecurity
 *
 *    This file is part of AuthenticRoast.
 *
 *    This library is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU Lesser General Public
 *    License as published by the Free Software Foundation; either
 *    version 3 of the License, or (at your option) any later version.
 *
 *    This library is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *    Lesser General Public License for more details.
 *
 *    You should have received a copy of the GNU Lesser General
 *    Public License along with this library; if not, write to the
 *    Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *    Boston, MA 02110-1301 USA
 *
 *    You can reach the author and get more information about this
 *    project at: http://aikesommer.name/
 */
package name.aikesommer.authenticator;

import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.CDI;
import javax.enterprise.util.AnnotationLiteral;
import javax.naming.InitialContext;
import javax.naming.NamingException;

public class CDIHelper {

	public static <T> T getReference(Class<T> beanClass) {
		return getReference(beanClass, getBeanManager());
	}

	public static <T> T getReferenceOrNull(Class<T> beanClass) {
		return getReferenceOrNull(beanClass, getBeanManager());
	}

	@SuppressWarnings("unchecked")
	public static <T> T getReference(Class<T> beanClass, BeanManager beanManager) {

		Bean<T> bean = (Bean<T>) beanManager.resolve(beanManager.getBeans(beanClass));
		return (T) beanManager.getReference(bean, beanClass, beanManager.createCreationalContext(bean));
	}

	@SuppressWarnings("unchecked")
	public static <T> T getReferenceOrNull(Class<T> beanClass, BeanManager beanManager) {
		try {
			Bean<T> bean = (Bean<T>) beanManager.resolve(beanManager.getBeans(beanClass));
			return (T) beanManager.getReference(bean, beanClass, beanManager.createCreationalContext(bean));
		} catch (Exception e) {
			return null;
		}
	}
	
	public static <T> T getInstance(final Class<T> type, final Class<? extends Annotation> scope, Annotation... qualifier) {
		return getInstance(type, scope, getBeanManager(), qualifier);
	}

	public static <T> T getInstance(final Class<T> type, final Class<? extends Annotation> scope) {
		return getInstance(type, scope, getBeanManager());
	}

	public static <T> T getInstance(final Class<T> type, final Class<? extends Annotation> scope, final BeanManager beanManager, Annotation... qualifier) {

		if(qualifier == null) {
			@SuppressWarnings("unchecked")
			Bean<T> bean = (Bean<T>) beanManager.resolve(beanManager.getBeans(type));
			return beanManager.getContext(scope).get(bean, beanManager.createCreationalContext(bean));
		} else {
			@SuppressWarnings("unchecked")
			Bean<T> bean = (Bean<T>) beanManager.resolve(beanManager.getBeans(type, qualifier));
			return beanManager.getContext(scope).get(bean, beanManager.createCreationalContext(bean));
		}
	}

	public static BeanManager tryGetBeanManager() {
		try {
			return getBeanManager();
		} catch (IllegalStateException e) {
			return null;
		}
	}

		public static BeanManager getBeanManager() {
		InitialContext context = null;
		try {
			context = new InitialContext();
			return (BeanManager) context.lookup("java:comp/BeanManager");
		} catch (NamingException e) {
			System.out.println("EE context not available. Falling back plain CDI.");
			return CDI.current().getBeanManager();
		} finally {
			closeContext(context);
		}
	}

	private static void closeContext(InitialContext context) {
		try {
			if (context != null) {
				context.close();
			}
		} catch (NamingException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static Instance<PluggableAuthenticator> getCdiAuthenticator() {
		Instance<PluggableAuthenticator> authenticator = CDI.current().select(PluggableAuthenticator.class, 
				new AnnotationLiteral<Primary>() {});
		return authenticator;
	}
}
